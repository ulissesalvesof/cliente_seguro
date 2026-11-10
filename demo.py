"""Demonstração local; sem servidor e sem fingir autenticação de rede."""
import os
from crypto_client import Client, AuthenticationError, ReplayError


def main():
    a, b, c = Client(), Client(), Client()
    try:
        for left, right in ((a, b), (a, c), (b, c)):
            salt = os.urandom(16)  # Simula entrega autenticada do mesmo salt ao par.
            left.add_peer(right.client_id, right.public_key, salt)
            right.add_peer(left.client_id, left.public_key, salt)
        frame = a.encrypt(b.client_id, b'')
        assert b.decrypt(frame) == (a.client_id, b'')
        print('[OK] A -> B: mensagem autenticada e decifrada')
        assert b.decrypt(a.encrypt(
            b.client_id, 'Teste com acentuação'.encode())) == (
                a.client_id, 'Teste com acentuação'.encode())
        assert a.decrypt(b.encrypt(a.client_id, b'resposta')) == (
            b.client_id, b'resposta')
        assert c.decrypt(a.encrypt(c.client_id, b'terceiro cliente')) == (
            a.client_id, b'terceiro cliente')
        print('[OK] Resposta e terceiro cliente')
        try:
            b.decrypt(frame)
        except ReplayError:
            print('[OK] Replay rejeitado')
        else:
            raise AssertionError('Replay deveria ter sido rejeitado')
        fresh = a.encrypt(b.client_id, b'teste de integridade')
        modified = fresh[:-1] + bytes([fresh[-1] ^ 1])
        try:
            b.decrypt(modified)
        except AuthenticationError:
            print('[OK] Adulteracao rejeitada por tag GCM')
        else:
            raise AssertionError('Frame adulterado deveria ter sido rejeitado')
        assert b.decrypt(fresh) == (a.client_id, b'teste de integridade')
        print('[OK] Frame legitimo aceito apos tentativa de adulteracao')
    finally:
        for client in (a, b, c):
            client.close()


if __name__ == '__main__':
    main()
