# Protocolo cliente-servidor implementado

Este documento descreve o formato atualmente usado por `network_client.py` e
`server/servidor.py`. O prefixo TCP uint32 big-endian conta apenas os bytes do
corpo. Todos os comprimentos são validados antes de ler o campo/corpo.

## Registro e handshake

1. Cliente envia um frame de 48 bytes: `client_id(16) || pk_client_X25519(32)`.
2. Servidor responde em um frame:
   `len(pk_server_DER)(4) || pk_server_DER || len(cert_DER)(4) || cert_DER ||
   len(signature)(2) || signature || salt_srv(16)`.
3. O cliente compara o certificado recebido com o pin exato configurado e
   verifica que a chave RSA informada corresponde à chave do certificado.
4. Material assinado: `pk_server_DER || pk_client_X25519 || client_id || salt_srv`.
   Assinatura: digest SHA-256 pré-calculado, RSA-PSS, MGF1-SHA256 e salt PSS de
   32 bytes. A chave RSA deve ter ao menos 2048 bits.

O mesmo `salt_srv` é usado por todas as sessões ativas do servidor para que cada
par derive chaves iguais. O salt é renovado quando não há sessões ativas. Uma
reconexão com peers ainda conectados recebe chaves X25519 novas, de modo que as
chaves E2E também mudam mesmo que o salt de época permaneça.

## Controles assinados

Cada controle é um frame independente. O corpo não assinado começa com
`TP3C || operation(1) || seq(8) || peer_id(16)`. Para `PEER_UP` (operação 1),
segue `peer_public_key(32)`; para `PEER_DOWN` (operação 2), não há chave.
Ao final vem uma assinatura RSA-PSS de tamanho correspondente à chave do
servidor. O digest assinado é SHA-256 de:

`"TP3-control-v1" || recipient_id(16) || salt_srv(16) || unsigned_control`.

O cliente valida assinatura, contexto e sequência antes de instalar/remover um
peer. Repetição ou controle antigo é rejeitado. A chave do peer é instalada
somente depois dessa validação.

## Derivação e mensagens E2E

Para cada par, os clientes calculam `Z = X25519(sk_local, pk_peer)`.
`PRK = HMAC-SHA256(salt_srv, Z)`. HKDF-Expand-SHA256 deriva 16 bytes com info
`A2B` e `B2A`; menor UUID binário é A. Chaves, contadores e prefixos IV são
independentes por peer/direção.

Frame E2E:

`nonce(12) || sender_id(16) || recipient_id(16) || seq_no(8) || ciphertext || tag(16)`

- `nonce = IV_base(4) || seq_no(8 big-endian)`
- `AAD = sender_id || recipient_id || seq_no`
- plaintext máximo: 4096 bytes; corpo E2E: 68–4164 bytes.
- sequência inicial: zero; o destinatário aceita somente sequência maior que a
  última autenticada. O estado local só avança após a tag GCM válida.
- o servidor verifica `sender_id` contra a conexão e o destinatário ativo, e
  encaminha os bytes originais sem decifrar.
- o destinatário é a autoridade anti-replay: como o servidor não pode validar
  a tag, ele não avança estado confiando em um contador E2E não autenticado.

## Fluxo e testes

Execute `python -m server.servidor` para iniciar o servidor e use
`NetworkClient.connect(host, port, pinned_certificate)` para conectar um cliente.
`receive_event()` produz anúncios de peer, remoções ou mensagens autenticadas;
`send(peer_id, plaintext_bytes)` cifra e envia.

`python -m unittest discover -v` executa testes unitários e de integração,
incluindo pin/assinatura, troca E2E, bitflip, replay, spoofing, reconexão e
framing inválido.

## Limites do modelo

O servidor é um diretório confiável: assinaturas impedem adulteração dos
controles por terceiros, mas um servidor malicioso ainda pode anunciar chaves
falsas. O certificado precisa ser distribuído e pinado por canal confiável.
O protocolo não autentica usuários, não esconde metadados e não implementa
ratchet ou persistência.
