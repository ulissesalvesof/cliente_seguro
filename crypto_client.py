"""Núcleo E2E. Não depende do formato das mensagens de controle do servidor."""
import os
import hashlib
import hmac
import struct
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

MAX_PLAINTEXT = 4096
HEADER = struct.Struct('!12s16s16sQ')
MAX_E2E_FRAME = HEADER.size + MAX_PLAINTEXT + 16


class ProtocolError(ValueError):
    """Frame rejeitado; o estado de recepção permanece intacto."""


class ReplayError(ProtocolError):
    pass


class AuthenticationError(ProtocolError):
    pass


@dataclass(repr=False)
class Peer:
    public_key: bytes
    key_send: bytes
    key_recv: bytes
    iv_send: bytes
    iv_recv: bytes | None = None
    seq_send: int = 0
    seq_recv: int = -1


class Client:
    """Uma instância por conexão/sessão. Uso em um único event loop/thread."""

    def __init__(self, client_id: uuid.UUID | None = None):
        self.client_id = client_id or uuid.uuid4()
        if self.client_id.version != 4:
            raise ValueError('client_id deve ser UUID v4')
        self._private = X25519PrivateKey.generate()
        self.public_key = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.peers: dict[uuid.UUID, Peer] = {}

    def add_peer(self, peer_id: uuid.UUID, public_key: bytes, salt: bytes):
        """Somente chamar com registro autenticado e fresco vindo do adaptador.

        Salt de 16 bytes deve ser o MESMO nos dois lados do par. Uma sessão
        instalada não pode ser sobrescrita: isso zeraria os contadores.
        Para renovação, fechar a sessão local e gerar novo Client.
        """
        if self._private is None:
            raise ProtocolError('Sessão encerrada')
        if peer_id == self.client_id or peer_id.version != 4:
            raise ProtocolError('ID de peer inválido')
        if peer_id in self.peers:
            raise ProtocolError('Peer já instalado; renovação exige nova sessão local')
        self.peers[peer_id] = self._derive_peer(peer_id, public_key, salt)

    def _derive_peer(self, peer_id: uuid.UUID, public_key: bytes, salt: bytes) -> Peer:
        if len(public_key) != 32 or len(salt) != 16:
            raise ProtocolError('Chave pública ou salt com tamanho inválido')
        try:
            secret = self._private.exchange(X25519PublicKey.from_public_bytes(public_key))
        except ValueError as exc:
            raise ProtocolError('Chave X25519 inválida') from exc
        prk = hmac.digest(salt, secret, hashlib.sha256)
        a2b = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=b'A2B').derive(prk)
        b2a = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=b'B2A').derive(prk)
        send, recv = (a2b, b2a) if self.client_id.bytes < peer_id.bytes else (b2a, a2b)
        # secret e prk não são armazenados. Python não garante apagamento físico.
        return Peer(public_key, send, recv, os.urandom(4))

    def update_peer(self, peer_id: uuid.UUID, public_key: bytes, salt: bytes):
        """Instala uma nova sessão autenticada de peer sem reutilizar estado antigo."""
        existing = self.peers.get(peer_id)
        if existing is not None and existing.public_key == public_key:
            return
        if self._private is None:
            raise ProtocolError('Sessão encerrada')
        if peer_id == self.client_id or peer_id.version != 4:
            raise ProtocolError('ID de peer inválido')
        replacement = self._derive_peer(peer_id, public_key, salt)
        self.peers[peer_id] = replacement

    def remove_peer(self, peer_id: uuid.UUID):
        self.peers.pop(peer_id, None)

    def encrypt(self, recipient: uuid.UUID, plaintext: bytes) -> bytes:
        if len(plaintext) > MAX_PLAINTEXT:
            raise ProtocolError('Mensagem excede 4096 bytes')
        peer = self.peers.get(recipient)
        if peer is None:
            raise ProtocolError('Destinatário desconhecido')
        seq = peer.seq_send
        if seq >= 2**64:
            raise ProtocolError('Contador esgotado; iniciar nova sessão')
        # Reservar antes de cifrar/enviar: falha posterior nunca permite reuso.
        peer.seq_send += 1
        seq_bytes = seq.to_bytes(8, 'big')
        nonce = peer.iv_send + seq_bytes
        aad = self.client_id.bytes + recipient.bytes + seq_bytes
        encrypted = AESGCM(peer.key_send).encrypt(nonce, plaintext, aad)
        return HEADER.pack(nonce, self.client_id.bytes, recipient.bytes, seq) + encrypted

    def decrypt(self, frame: bytes) -> tuple[uuid.UUID, bytes]:
        if not HEADER.size + 16 <= len(frame) <= MAX_E2E_FRAME:
            raise ProtocolError('Tamanho E2E inválido')
        nonce, sender_raw, recipient_raw, seq = HEADER.unpack_from(frame)
        sender = uuid.UUID(bytes=sender_raw)
        if recipient_raw != self.client_id.bytes:
            raise ProtocolError('Destinatário incorreto')
        peer = self.peers.get(sender)
        if peer is None:
            raise ProtocolError('Remetente desconhecido')
        if seq <= peer.seq_recv:
            raise ReplayError('Sequência repetida ou antiga')
        seq_bytes = seq.to_bytes(8, 'big')
        if nonce[4:] != seq_bytes:
            raise ProtocolError('Nonce inconsistente com sequência')
        if peer.iv_recv is not None and nonce[:4] != peer.iv_recv:
            raise ProtocolError('Prefixo de nonce mudou na sessão')
        aad = sender_raw + recipient_raw + seq_bytes
        try:
            plaintext = AESGCM(peer.key_recv).decrypt(nonce, frame[HEADER.size:], aad)
        except InvalidTag as exc:
            raise AuthenticationError('Tag GCM inválida') from exc
        # Fixar IV e avançar contador apenas DEPOIS da autenticação.
        peer.iv_recv = nonce[:4]
        peer.seq_recv = seq
        return sender, plaintext

    def close(self):
        """Descarta referências. Não promete zeroização da memória Python."""
        self.peers.clear()
        self._private = None
