"""TCP adapter for the E2E client and the server protocol in server/servidor.py."""
import asyncio
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_client import (
    MAX_E2E_FRAME,
    AuthenticationError,
    Client,
    ProtocolError,
)
from framing import read_frame, write_frame
from server_auth import (
    PEER_DOWN,
    PEER_UP,
    CONTROL_MAGIC,
    load_certificate,
    verify_handshake,
    verify_peer_control,
)

MAX_HANDSHAKE_FRAME = 16 * 1024


class NetworkClient:
    """One TCP connection; call methods from a single asyncio event loop."""

    def __init__(self, client: Client, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, salt: bytes,
                 server_key: rsa.RSAPublicKey):
        self.client = client
        self.reader = reader
        self.writer = writer
        self.salt = salt
        self.server_key = server_key
        self.last_control_seq = -1
        self._write_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def connect(cls, host: str, port: int, pinned_certificate: bytes,
                      timeout: float = 15,
                      client_id: uuid.UUID | None = None) -> 'NetworkClient':
        client = Client(client_id)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        try:
            registration = client.client_id.bytes + client.public_key
            await write_frame(writer, registration, 48)
            response = await read_frame(reader, MAX_HANDSHAKE_FRAME, timeout)
            server_key_der, cert_data, signature, salt = cls._parse_handshake(response)
            verify_handshake(
                cert_data,
                pinned_certificate,
                signature,
                client.public_key,
                client.client_id,
                salt,
                server_key_der,
            )
            server_key = load_certificate(cert_data).public_key()
            if not isinstance(server_key, rsa.RSAPublicKey):
                raise AuthenticationError('A chave do servidor não é RSA')
            return cls(client, reader, writer, salt, server_key)
        except BaseException:
            client.close()
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            raise

    @staticmethod
    def _parse_handshake(body: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        offset = 0

        def take_length(maximum: int, width: int = 4) -> bytes:
            nonlocal offset
            if offset + width > len(body):
                raise ProtocolError('Handshake truncado')
            length = int.from_bytes(body[offset:offset + width], 'big')
            offset += width
            if not 0 < length <= maximum or offset + length > len(body):
                raise ProtocolError('Campo de handshake inválido')
            value = body[offset:offset + length]
            offset += length
            return value

        server_key = take_length(2048)
        certificate = take_length(8192)
        signature = take_length(1024, 2)
        if offset + 16 != len(body):
            raise ProtocolError('Tamanho de handshake inválido')
        salt = body[offset:]
        return server_key, certificate, signature, salt

    async def send(self, recipient: uuid.UUID, plaintext: bytes):
        if self._closed:
            raise ProtocolError('Conexão encerrada')
        frame = self.client.encrypt(recipient, plaintext)
        async with self._write_lock:
            await write_frame(self.writer, frame, len(frame))

    async def receive_event(self):
        """Return ('peer_up'|'peer_down', peer_id) or ('message', sender, plaintext)."""
        if self._closed:
            raise ProtocolError('Conexão encerrada')
        try:
            body = await read_frame(self.reader, MAX_E2E_FRAME, timeout=None)
        except ProtocolError:
            await self.close()
            raise

        if body.startswith(CONTROL_MAGIC):
            try:
                operation, sequence, peer_bytes, public_key = verify_peer_control(
                    body, self.server_key, self.client.client_id.bytes, self.salt)
            except AuthenticationError:
                pass
            else:
                if sequence <= self.last_control_seq:
                    raise ProtocolError('Mensagem de controle repetida ou antiga')
                peer_id = uuid.UUID(bytes=peer_bytes)
                if peer_id == self.client.client_id or peer_id.version != 4:
                    raise ProtocolError('ID de peer inválido no controle')
                if operation == PEER_UP:
                    if public_key is None:
                        raise ProtocolError('Anúncio sem chave pública')
                    self.client.update_peer(peer_id, public_key, self.salt)
                    self.last_control_seq = sequence
                    return 'peer_up', peer_id
                if operation == PEER_DOWN:
                    self.client.remove_peer(peer_id)
                    self.last_control_seq = sequence
                    return 'peer_down', peer_id
                raise ProtocolError('Operação de controle inválida')

        sender, plaintext = self.client.decrypt(body)
        return 'message', sender, plaintext

    async def close(self):
        if self._closed:
            return
        self._closed = True
        self.client.close()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionError:
            pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.close()
