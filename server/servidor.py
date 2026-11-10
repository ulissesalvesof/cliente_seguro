"""Authenticated rendezvous and opaque E2E relay for TP3."""
import asyncio
import contextlib
import datetime
import hashlib
import os
import struct
import uuid
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils, x25519
from cryptography.x509.oid import NameOID

from crypto_client import AuthenticationError, ProtocolError
from server_auth import (
    PEER_DOWN,
    PEER_UP,
    sign_peer_control,
)

SERVER_HOST = os.environ.get('TP3_HOST', '127.0.0.1')
SERVER_PORT = int(os.environ.get('TP3_PORT', '8888'))
SALT_LENGTH = 16
MAX_PLAINTEXT = 4096
MAX_CLIENTS = 50
MIN_E2E_FRAME = 68
MAX_E2E_FRAME = 4164
MAX_HANDSHAKE_FRAME = 48
HANDSHAKE_TIMEOUT = 15
CERT_FILE = Path(__file__).resolve().with_name('server.crt')
KEY_FILE = Path(__file__).resolve().with_name('server.key')

sessions: dict[bytes, dict[str, Any]] = {}
session_lock = asyncio.Lock()
current_server_salt = os.urandom(SALT_LENGTH)


def _log(level: str, message: str):
    print(f'[{level}] {message}', flush=True)


def get_fingerprint(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()[:12]


def load_or_generate_server_identity(cert_file: Path = CERT_FILE,
                                     key_file: Path = KEY_FILE):
    cert_exists = cert_file.exists()
    key_exists = key_file.exists()
    if cert_exists != key_exists:
        raise RuntimeError('server.crt e server.key devem existir juntos; não os substitua automaticamente')
    if cert_exists:
        private_key = serialization.load_pem_private_key(
            key_file.read_bytes(), password=None)
        cert_data = cert_file.read_bytes()
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except ValueError:
            cert = x509.load_pem_x509_certificate(cert_data)
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 2048:
            raise RuntimeError('A chave privada do servidor deve ser RSA de pelo menos 2048 bits')
        cert_key = cert.public_key()
        if not isinstance(cert_key, rsa.RSAPublicKey):
            raise RuntimeError('O certificado do servidor não contém chave RSA')
        if cert_key.public_numbers() != private_key.public_key().public_numbers():
            raise RuntimeError('server.key não corresponde a server.crt')
        _log('*', 'Identidade RSA do servidor carregada.')
        return private_key, cert

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Servidor Mensageria Segura E2E'),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    key_file.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    _log('*', 'Identidade RSA e certificado DER gerados.')
    return private_key, cert


def _pack_frame(body: bytes) -> bytes:
    if not 0 < len(body) <= 0xFFFFFFFF:
        raise ProtocolError('Comprimento de frame inválido')
    return struct.pack('!I', len(body)) + body


async def _read_frame(reader: asyncio.StreamReader, maximum: int,
                      minimum: int = 1,
                      timeout: float | None = HANDSHAKE_TIMEOUT) -> bytes:
    phase = 'prefix'

    async def read():
        nonlocal phase
        prefix = await reader.readexactly(4)
        length = struct.unpack('!I', prefix)[0]
        if not minimum <= length <= maximum:
            raise ProtocolError('Comprimento de frame inválido')
        phase = 'body'
        return await reader.readexactly(length)

    try:
        return await asyncio.wait_for(read(), timeout)
    except asyncio.IncompleteReadError as exc:
        if phase == 'prefix' and not exc.partial:
            raise
        raise ProtocolError('Frame incompleto') from exc
    except TimeoutError as exc:
        raise ProtocolError('Frame incompleto ou timeout') from exc


async def _write_session(session: dict[str, Any], body: bytes):
    async with session['write_lock']:
        session['writer'].write(_pack_frame(body))
        await session['writer'].drain()


def _sign_handshake(private_key: rsa.RSAPrivateKey, public_key_der: bytes,
                    client_key: bytes, client_id: bytes, salt: bytes) -> bytes:
    digest = hashlib.sha256(public_key_der + client_key + client_id + salt).digest()
    return private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        utils.Prehashed(hashes.SHA256()),
    )


async def _send_peer_control(recipient_id: bytes, operation: int, peer_id: bytes,
                             public_key: bytes | None, private_key: rsa.RSAPrivateKey):
    recipient = sessions.get(recipient_id)
    if recipient is None:
        return
    sequence = recipient['seq_send']
    if sequence >= 2**64:
        raise ProtocolError('Contador administrativo esgotado')
    payload = sign_peer_control(
        private_key,
        recipient_id,
        recipient['salt'],
        sequence,
        operation,
        peer_id,
        public_key,
    )
    recipient['seq_send'] += 1
    await _write_session(recipient, payload)


async def notify_peers_and_share_keys(new_client_id: bytes,
                                      private_key: rsa.RSAPrivateKey):
    new_session = sessions[new_client_id]
    for peer_id, peer_session in list(sessions.items()):
        if peer_id == new_client_id:
            continue
        await _send_peer_control(
            peer_id, PEER_UP, new_client_id, new_session['public_key'], private_key)
        await _send_peer_control(
            new_client_id, PEER_UP, peer_id, peer_session['public_key'], private_key)


async def perform_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            private_key: rsa.RSAPrivateKey,
                            cert: x509.Certificate) -> bytes:
    global current_server_salt
    registration = await _read_frame(reader, MAX_HANDSHAKE_FRAME,
                                     MAX_HANDSHAKE_FRAME)
    client_id, client_key = registration[:16], registration[16:]
    if uuid.UUID(bytes=client_id).version != 4:
        raise ProtocolError('client_id deve ser UUID v4')
    try:
        public_key = x25519.X25519PublicKey.from_public_bytes(client_key)
        x25519.X25519PrivateKey.generate().exchange(public_key)
    except ValueError as exc:
        raise ProtocolError('Chave pública X25519 inválida') from exc

    public_key_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    async with session_lock:
        if len(sessions) >= MAX_CLIENTS:
            raise ProtocolError('Capacidade máxima de clientes atingida')
        if client_id in sessions:
            raise ProtocolError('client_id já possui uma sessão ativa')
        if not sessions:
            current_server_salt = os.urandom(SALT_LENGTH)
        salt = current_server_salt
        signature = _sign_handshake(
            private_key, public_key_der, client_key, client_id, salt)
        response = (
            struct.pack('!I', len(public_key_der)) + public_key_der
            + struct.pack('!I', len(cert_der)) + cert_der
            + struct.pack('!H', len(signature)) + signature + salt
        )
        writer.write(_pack_frame(response))
        await writer.drain()
        sessions[client_id] = {
            'writer': writer,
            'public_key': client_key,
            'seq_send': 0,
            'salt': salt,
            'write_lock': asyncio.Lock(),
        }

    _log('+', f'Cliente {client_id.hex()[:8]} registrado; pk fingerprint {get_fingerprint(client_key)}.')
    return client_id


async def handle_e2e_traffic(reader: asyncio.StreamReader, client_id: bytes):
    while True:
        frame = await _read_frame(
            reader, MAX_E2E_FRAME, MIN_E2E_FRAME, timeout=None)
        session = sessions.get(client_id)
        if session is None:
            raise ProtocolError('Sessão não está mais ativa')
        sender_id = frame[12:28]
        recipient_id = frame[28:44]
        sequence = struct.unpack('!Q', frame[44:52])[0]
        if sender_id != client_id:
            raise AuthenticationError('sender_id não corresponde à conexão autenticada')
        if frame[4:12] != struct.pack('!Q', sequence):
            raise ProtocolError('Nonce inconsistente com a sequência')
        if recipient_id == client_id or recipient_id not in sessions:
            raise ProtocolError('Destinatário desconhecido ou inválido')
        recipient = sessions[recipient_id]
        await _write_session(recipient, frame)
        _log('*', f'Relay E2E {len(frame)} bytes; {client_id.hex()[:8]} -> {recipient_id.hex()[:8]}; seq={sequence}.')


async def _remove_session(client_id: bytes, writer: asyncio.StreamWriter,
                          private_key: rsa.RSAPrivateKey):
    async with session_lock:
        session = sessions.get(client_id)
        if session is None or session['writer'] is not writer:
            return
        del sessions[client_id]
        for peer_id in list(sessions):
            try:
                await _send_peer_control(
                    peer_id, PEER_DOWN, client_id, None, private_key)
            except (ConnectionError, OSError):
                _log('!', f'Falha ao notificar peer {peer_id.hex()[:8]} sobre desconexão.')
        _log('+', f'Sessão {client_id.hex()[:8]} removida.')


async def client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         private_key: rsa.RSAPrivateKey, cert: x509.Certificate):
    client_id = None
    address = writer.get_extra_info('peername')
    _log('*', f'Conexão recebida de {address}.')
    try:
        client_id = await perform_handshake(reader, writer, private_key, cert)
        await notify_peers_and_share_keys(client_id, private_key)
        await handle_e2e_traffic(reader, client_id)
    except ProtocolError as exc:
        _log('!', f'Conexão rejeitada ({client_id.hex()[:8] if client_id else address}): {exc}.')
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        _log('*', f'Conexão encerrada ({client_id.hex()[:8] if client_id else address}).')
    except Exception as exc:
        _log('-', f'Erro na sessão ({client_id.hex()[:8] if client_id else address}): {exc}.')
    finally:
        try:
            if client_id is not None:
                await _remove_session(client_id, writer, private_key)
        except Exception as exc:
            _log('-', f'Falha ao limpar sessão ({client_id.hex()[:8]}): {exc}.')
        finally:
            with contextlib.suppress(ConnectionError):
                writer.close()
                await writer.wait_closed()


async def main(host: str = SERVER_HOST, port: int = SERVER_PORT):
    private_key, cert = load_or_generate_server_identity()
    server = await asyncio.start_server(
        lambda reader, writer: client_handler(reader, writer, private_key, cert),
        host, port,
    )
    _log('+', f'Servidor ativo em {host}:{port}.')
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[*] Servidor encerrado pelo usuário.', flush=True)
