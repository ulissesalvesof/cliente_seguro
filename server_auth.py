"""Certificate pinning and signed server-control messages."""
import hashlib
import hmac
import struct
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from crypto_client import AuthenticationError

CONTROL_MAGIC = b'TP3C'
PEER_UP = 1
PEER_DOWN = 2
CONTROL_DOMAIN = b'TP3-control-v1'
PEER_UP_BODY = struct.Struct('!4sBQ16s32s')
PEER_DOWN_BODY = struct.Struct('!4sBQ16s')


def load_certificate(data: bytes) -> x509.Certificate:
    try:
        if data.lstrip().startswith(b'-----BEGIN CERTIFICATE-----'):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise AuthenticationError('Certificado inválido') from exc


def handshake_material(public_key: rsa.RSAPublicKey, client_key: bytes,
                       client_id: uuid.UUID, salt: bytes) -> bytes:
    if len(client_key) != 32 or len(salt) != 16:
        raise ValueError('Tamanho inválido no handshake')
    pk_server = public_key.public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return pk_server + client_key + client_id.bytes + salt


def verify_handshake(cert_data: bytes, pinned_data: bytes, signature: bytes,
                     client_key: bytes, client_id: uuid.UUID, salt: bytes,
                     server_public_key_der: bytes | None = None):
    """Verify the pinned certificate and RSA-PSS signature over SHA256(material)."""
    try:
        cert = load_certificate(cert_data)
        pinned = load_certificate(pinned_data)
        if not hmac.compare_digest(cert.fingerprint(hashes.SHA256()),
                                   pinned.fingerprint(hashes.SHA256())):
            raise AuthenticationError('Certificado diferente do pin')
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise AuthenticationError('Chave RSA deve ter pelo menos 2048 bits')
        cert_public_key_der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        if (server_public_key_der is not None
                and not hmac.compare_digest(cert_public_key_der, server_public_key_der)):
            raise AuthenticationError('Chave pública não corresponde ao certificado')
        digest = hashlib.sha256(
            handshake_material(key, client_key, client_id, salt)).digest()
        key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            utils.Prehashed(hashes.SHA256()),
        )
    except AuthenticationError:
        raise
    except (ValueError, InvalidSignature) as exc:
        raise AuthenticationError('Handshake inválido') from exc


def control_signing_material(unsigned_payload: bytes, recipient_id: bytes,
                             salt: bytes) -> bytes:
    if len(recipient_id) != 16 or len(salt) != 16:
        raise ValueError('Tamanho inválido no controle')
    return CONTROL_DOMAIN + recipient_id + salt + unsigned_payload


def sign_peer_control(private_key: rsa.RSAPrivateKey, recipient_id: bytes,
                      salt: bytes, sequence: int, operation: int,
                      peer_id: bytes, public_key: bytes | None = None) -> bytes:
    if operation == PEER_UP:
        if public_key is None or len(public_key) != 32:
            raise ValueError('Chave pública de peer inválida')
        unsigned = PEER_UP_BODY.pack(
            CONTROL_MAGIC, operation, sequence, peer_id, public_key)
    elif operation == PEER_DOWN:
        unsigned = PEER_DOWN_BODY.pack(
            CONTROL_MAGIC, operation, sequence, peer_id)
    else:
        raise ValueError('Operação de controle inválida')
    digest = hashlib.sha256(
        control_signing_material(unsigned, recipient_id, salt)).digest()
    signature = private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        utils.Prehashed(hashes.SHA256()),
    )
    return unsigned + signature


def verify_peer_control(payload: bytes, server_key: rsa.RSAPublicKey,
                        recipient_id: bytes, salt: bytes):
    """Return (operation, sequence, peer_id, public_key-or-None) after verification."""
    signature_length = (server_key.key_size + 7) // 8
    if len(payload) < 5 + 8 + 16 + signature_length:
        raise AuthenticationError('Controle truncado')
    unsigned, signature = payload[:-signature_length], payload[-signature_length:]
    if unsigned[:4] != CONTROL_MAGIC:
        raise AuthenticationError('Controle desconhecido')
    operation = unsigned[4]
    if operation == PEER_UP:
        expected = PEER_UP_BODY.size
        if len(unsigned) != expected:
            raise AuthenticationError('Anúncio de peer inválido')
        _, _, sequence, peer_id, public_key = PEER_UP_BODY.unpack(unsigned)
    elif operation == PEER_DOWN:
        expected = PEER_DOWN_BODY.size
        if len(unsigned) != expected:
            raise AuthenticationError('Remoção de peer inválida')
        _, _, sequence, peer_id = PEER_DOWN_BODY.unpack(unsigned)
        public_key = None
    else:
        raise AuthenticationError('Operação de controle desconhecida')
    digest = hashlib.sha256(
        control_signing_material(unsigned, recipient_id, salt)).digest()
    try:
        server_key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            utils.Prehashed(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise AuthenticationError('Assinatura de controle inválida') from exc
    return operation, sequence, peer_id, public_key
