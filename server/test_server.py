"""In-process integration tests for the real server and NetworkClient."""
import asyncio
import datetime
import struct
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from crypto_client import AuthenticationError, ReplayError
from framing import pack_frame
from network_client import NetworkClient
from server import servidor


class ServerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'TP3 integration test'),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cls.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(cls.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(cls.private_key, hashes.SHA256())
        )
        cls.pin = cls.cert.public_bytes(serialization.Encoding.DER)

    async def asyncSetUp(self):
        servidor.sessions.clear()
        self.server = await asyncio.start_server(
            lambda reader, writer: servidor.client_handler(
                reader, writer, self.private_key, self.cert),
            '127.0.0.1', 0,
        )
        self.port = self.server.sockets[0].getsockname()[1]
        self.a = await NetworkClient.connect('127.0.0.1', self.port, self.pin)
        self.b = await NetworkClient.connect('127.0.0.1', self.port, self.pin)
        self.assertEqual(await self.a.receive_event(),
                         ('peer_up', self.b.client.client_id))
        self.assertEqual(await self.b.receive_event(),
                         ('peer_up', self.a.client.client_id))

    async def asyncTearDown(self):
        await self.a.close()
        await self.b.close()
        self.server.close()
        await self.server.wait_closed()
        await asyncio.sleep(0)
        servidor.sessions.clear()

    async def test_authenticated_handshake_and_bidirectional_e2e(self):
        message = 'Olá, integração E2E'.encode()
        await self.a.send(self.b.client.client_id, message)
        self.assertEqual(
            await self.b.receive_event(),
            ('message', self.a.client.client_id, message),
        )
        reply = b'resposta'
        await self.b.send(self.a.client.client_id, reply)
        self.assertEqual(
            await self.a.receive_event(),
            ('message', self.b.client.client_id, reply),
        )

    async def test_bitflip_is_rejected_without_advancing_receive_state(self):
        recipient = self.b.client.client_id
        frame = self.a.client.encrypt(recipient, b'tamper target')
        damaged = frame[:-1] + bytes([frame[-1] ^ 1])
        self.a.writer.write(pack_frame(damaged, 4164))
        await self.a.writer.drain()
        with self.assertRaises(AuthenticationError):
            await self.b.receive_event()
        self.assertEqual(
            self.b.client.peers[self.a.client.client_id].seq_recv, -1)

        valid = b'valid after tamper'
        await self.a.send(recipient, valid)
        self.assertEqual(
            await self.b.receive_event(),
            ('message', self.a.client.client_id, valid),
        )

    async def test_replay_is_rejected_by_recipient_without_poisoning_state(self):
        recipient = self.b.client.client_id
        frame = self.a.client.encrypt(recipient, b'one delivery')
        packet = pack_frame(frame, 4164)
        self.a.writer.write(packet + packet)
        await self.a.writer.drain()
        self.assertEqual(
            await self.b.receive_event(),
            ('message', self.a.client.client_id, b'one delivery'),
        )
        with self.assertRaises(ReplayError):
            await self.b.receive_event()
        self.assertIn(self.a.client.client_id.bytes, servidor.sessions)
        await self.a.send(recipient, b'next legitimate message')
        self.assertEqual(
            await self.b.receive_event(),
            ('message', self.a.client.client_id, b'next legitimate message'),
        )

    async def test_reconnect_with_same_id_replaces_peer_keys(self):
        client_id = self.a.client.client_id
        old_public_key = self.a.client.public_key
        old_frame = self.a.client.encrypt(self.b.client.client_id, b'old session')
        await self.a.close()
        for _ in range(50):
            if client_id.bytes not in servidor.sessions:
                break
            await asyncio.sleep(0.02)
        self.assertEqual(await self.b.receive_event(), ('peer_down', client_id))

        self.a = await NetworkClient.connect(
            '127.0.0.1', self.port, self.pin, client_id=client_id)
        self.assertNotEqual(self.a.client.public_key, old_public_key)
        self.assertEqual(await self.b.receive_event(), ('peer_up', client_id))
        self.assertEqual(
            await self.a.receive_event(),
            ('peer_up', self.b.client.client_id),
        )
        with self.assertRaises(AuthenticationError):
            self.b.client.decrypt(old_frame)
        await self.a.send(self.b.client.client_id, b'new session')
        self.assertEqual(
            await self.b.receive_event(),
            ('message', client_id, b'new session'),
        )

    async def test_sender_spoofing_closes_connection(self):
        frame = bytearray(self.a.client.encrypt(
            self.b.client.client_id, b'spoof attempt'))
        frame[12:28] = self.b.client.client_id.bytes
        self.a.writer.write(pack_frame(bytes(frame), 4164))
        await self.a.writer.drain()
        for _ in range(50):
            if self.a.client.client_id.bytes not in servidor.sessions:
                break
            await asyncio.sleep(0.02)
        self.assertNotIn(self.a.client.client_id.bytes, servidor.sessions)

    async def test_invalid_framing_disconnects_safely(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(struct.pack('!I', 5) + b'12345')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        writer.close()
        await writer.wait_closed()

    async def test_unpinned_certificate_is_rejected(self):
        bad_pin = b'not a certificate'
        with self.assertRaises(AuthenticationError):
            await NetworkClient.connect('127.0.0.1', self.port, bad_pin)


if __name__ == '__main__':
    unittest.main()
