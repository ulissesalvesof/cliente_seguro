# Servidor E2E

`servidor.py` implementa o relay TCP e rendezvous. Ele mantém conexões e chaves
públicas X25519 em memória, mas não deriva chaves AES nem decifra mensagens.

## Executar

Na raiz do projeto:

```powershell
python -m server.servidor
```

O padrão é `127.0.0.1:8888`. `TP3_HOST` e `TP3_PORT` configuram endereço e porta.
O servidor carrega `server.crt` (DER) e `server.key` (PEM) desta pasta ou gera
o par quando ambos ainda não existem. Se apenas um existir, a inicialização
falha para evitar substituição acidental da identidade.

`server.key` é a chave privada RSA do servidor, sem senha nesta versão. Mantenha
o arquivo restrito ao servidor e nunca o compartilhe. Clientes recebem somente
o certificado público; instale uma cópia confiável de `server.crt` no cliente.

## Fluxo e controles

1. O cliente envia, em frame TCP, UUID v4 (16 bytes) e chave X25519 raw (32 bytes).
2. O servidor envia chave RSA pública DER, certificado DER, assinatura RSA-PSS
   e salt, em uma resposta TCP enquadrada.
3. O cliente verifica o pin e a assinatura sobre
   `SHA256(pk_server_DER || pk_client || client_id || salt)`.
4. Anúncios e remoções de peers são assinados e vinculados ao cliente destinatário,
   ao salt da sessão e a um contador monotônico.
5. O servidor valida tamanho, remetente associado à conexão, destinatário ativo
   e consistência estrutural de nonce/contador antes de encaminhar o frame.
6. Desconexão remove a sessão e envia anúncio assinado de remoção aos peers.

Frames E2E válidos têm de 68 a 4164 bytes. O destinatário verifica replay e a
tag AES-GCM antes de avançar o estado. O servidor não trata o contador recebido
como autenticado, pois não pode validar a tag sem quebrar a propriedade E2E;
isso evita que um frame forjado avance o estado do relay e bloqueie mensagens.

## Testes integrados

Da raiz:

```powershell
python -m unittest server.test_server -v
```

Os testes iniciam o servidor em uma porta local efêmera e cobrem handshake com
pin, troca bidirecional, anúncio/remoção e reconexão, bitflip, replay rejeitado
no destinatário sem envenenar estado, spoofing de remetente e framing inválido.
Não é necessário iniciar um servidor separado.
