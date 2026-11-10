import asyncio
import datetime
import hashlib
import os
import struct
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.x509.oid import NameOID

from crypto_client import Client, ProtocolError, ReplayError, AuthenticationError, MAX_E2E_FRAME
from framing import pack_frame, read_frame
from server_auth import handshake_material, verify_handshake


def pair():
    a, b = Client(), Client()
    salt = os.urandom(16)
    a.add_peer(b.client_id, b.public_key, salt)
    b.add_peer(a.client_id, a.public_key, salt)
    return a, b


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = pair()

    def test_roundtrip_and_direction(self):
        a, b = self.a, self.b
        self.assertEqual(a.peers[b.client_id].key_send, b.peers[a.client_id].key_recv)
        self.assertNotEqual(a.peers[b.client_id].key_send, a.peers[b.client_id].key_recv)
        for data in (b'', 'Olá'.encode(), b'x' * 4096):
            self.assertEqual(b.decrypt(a.encrypt(b.client_id, data))[1], data)
            self.assertEqual(a.decrypt(b.encrypt(a.client_id, data))[1], data)

    def test_replay(self):
        frame = self.a.encrypt(self.b.client_id, b'test')
        self.b.decrypt(frame)
        with self.assertRaises(ReplayError):
            self.b.decrypt(frame)

    def test_tamper_does_not_advance_state(self):
        frame = self.a.encrypt(self.b.client_id, b'test')
        for position in (0, 51, 52, len(frame) - 1):
            modified = bytearray(frame)
            modified[position] ^= 1
            with self.assertRaises(ProtocolError):
                self.b.decrypt(bytes(modified))
            self.assertEqual(self.b.peers[self.a.client_id].seq_recv, -1)
            self.assertIsNone(self.b.peers[self.a.client_id].iv_recv)
        self.b.decrypt(frame)

    def test_limits_and_unknown(self):
        with self.assertRaises(ProtocolError):
            self.a.encrypt(self.b.client_id, b'x' * 4097)
        with self.assertRaises(ProtocolError):
            Client().decrypt(self.a.encrypt(self.b.client_id, b'x'))
        for frame in (b'', b'x' * (MAX_E2E_FRAME + 1)):
            with self.assertRaises(ProtocolError):
                self.b.decrypt(frame)

    def test_mismatched_salt(self):
        a, b = Client(), Client()
        a.add_peer(b.client_id, b.public_key, b'a' * 16)
        b.add_peer(a.client_id, a.public_key, b'b' * 16)
        with self.assertRaises(AuthenticationError):
            b.decrypt(a.encrypt(b.client_id, b'x'))

    def test_duplicate_and_null_key(self):
        with self.assertRaises(ProtocolError):
            self.a.add_peer(self.b.client_id, self.b.public_key, os.urandom(16))
        c = Client()
        with self.assertRaises(ProtocolError):
            self.a.add_peer(c.client_id, bytes(32), os.urandom(16))

    def test_reconnect_fresh_keys_and_old_frame(self):
        a, b = self.a, self.b
        old = a.encrypt(b.client_id, b'old')
        new_a, new_b = Client(a.client_id), Client(b.client_id)
        salt = os.urandom(16)
        new_a.add_peer(new_b.client_id, new_b.public_key, salt)
        new_b.add_peer(new_a.client_id, new_a.public_key, salt)
        with self.assertRaises(AuthenticationError):
            new_b.decrypt(old)
        new_b.decrypt(new_a.encrypt(new_b.client_id, b'new'))
        self.assertNotEqual(a.public_key, new_a.public_key)

    def test_authenticated_peer_update_replaces_keys_safely(self):
        old_frame = self.a.encrypt(self.b.client_id, b'old peer session')
        new_b = Client(self.b.client_id)
        salt = os.urandom(16)
        self.a.update_peer(new_b.client_id, new_b.public_key, salt)
        new_b.add_peer(self.a.client_id, self.a.public_key, salt)
        with self.assertRaises(ProtocolError):
            self.a.update_peer(new_b.client_id, bytes(32), salt)
        with self.assertRaises(AuthenticationError):
            new_b.decrypt(old_frame)
        frame = self.a.encrypt(new_b.client_id, b'new peer session')
        self.assertEqual(new_b.decrypt(frame)[1], b'new peer session')

    def test_overflow_and_close(self):
        self.a.peers[self.b.client_id].seq_send = 2**64
        with self.assertRaises(ProtocolError):
            self.a.encrypt(self.b.client_id, b'x')
        self.a.close()
        with self.assertRaises(ProtocolError):
            self.a.add_peer(self.b.client_id, self.b.public_key, os.urandom(16))


class FramingTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_and_coalesced(self):
        reader = asyncio.StreamReader()
        async def feed():
            data = pack_frame(b'abc', 10) + pack_frame(b'de', 10)
            for byte in data:
                reader.feed_data(bytes([byte]))
                await asyncio.sleep(0)
            reader.feed_eof()
        task = asyncio.create_task(feed())
        self.assertEqual(await read_frame(reader, 10), b'abc')
        self.assertEqual(await read_frame(reader, 10), b'de')
        await task

    async def test_invalid_and_truncated(self):
        for data in (struct.pack('!I', 0), struct.pack('!I', 11),
                     struct.pack('!I', 5) + b'ab', b'\x00'):
            reader = asyncio.StreamReader()
            reader.feed_data(data)
            reader.feed_eof()
            with self.assertRaises(ProtocolError):
                await read_frame(reader, 10)

    async def test_timeout(self):
        with self.assertRaises(ProtocolError):
            await read_frame(asyncio.StreamReader(), 10, timeout=0.01)


class HandshakeTests(unittest.TestCase):
    def test_valid_invalid_signature_and_pin(self):
        def certificate(key, name):
            dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            now = datetime.datetime.now(datetime.timezone.utc)
            return (x509.CertificateBuilder().subject_name(dn).issuer_name(dn)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=1))
                    .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = certificate(key, 'servidor')
        other_cert = certificate(key, 'outro certificado')
        client = Client()
        salt = os.urandom(16)
        digest = hashlib.sha256(handshake_material(key.public_key(), client.public_key,
                                                  client.client_id, salt)).digest()
        sig = key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                       utils.Prehashed(hashes.SHA256()))
        args = (client.public_key, client.client_id, salt)
        verify_handshake(cert, cert, sig, *args)
        with self.assertRaises(AuthenticationError):
            verify_handshake(cert, other_cert, sig, *args)
        with self.assertRaises(AuthenticationError):
            verify_handshake(cert, cert, sig[:-1] + bytes([sig[-1] ^ 1]), *args)
        with self.assertRaises(AuthenticationError):
            verify_handshake(cert, cert, sig, client.public_key, client.client_id, b'x' * 16)


if __name__ == '__main__':
    unittest.main()
