# Mensageria segura E2E — Trabalho Prático 3

Implementação em Python 3.11+ do núcleo criptográfico, cliente TCP e relay
servidor. O servidor encaminha os frames E2E sem decifrá-los.

## Instalação e execução

No PowerShell, na raiz do projeto:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Demo criptográfica local (sem rede):

```powershell
python demo.py
```

Iniciar o servidor:

```powershell
python -m server.servidor
```

Por padrão, o servidor escuta apenas em `127.0.0.1:8888`. Para disponibilizá-lo
em uma rede confiável, configure `TP3_HOST` e `TP3_PORT` conscientemente.
O certificado público pinado é `server/server.crt`; distribua-o por um canal
confiável e nunca distribua `server/server.key`.

Executar todos os testes unitários e de integração em memória:

```powershell
python -m unittest discover -v
```

## Organização

- `crypto_client.py`: X25519, ECDH, HKDF-SHA256, AES-128-GCM, frame E2E e anti-replay.
- `server_auth.py`: pin do certificado, handshake RSA-PSS e controles assinados.
- `framing.py`: framing TCP com prefixo uint32 big-endian.
- `network_client.py`: registro TCP, validação do servidor, controle de peers e envio/recepção E2E.
- `server/servidor.py`: registro, rendezvous, validação e encaminhamento opaco.
- `server/test_server.py`: testes de integração reais entre `NetworkClient` e servidor local.
- `tests/test_client.py`: testes unitários de criptografia, framing e handshake.
- `INTEGRACAO.md`: especificação do protocolo compartilhado.

## Protocolo implementado

O cliente registra `client_id` (UUID v4, 16 bytes) e chave pública X25519 raw
(32 bytes). O handshake e as mensagens usam TCP com prefixo de comprimento de
4 bytes big-endian. O servidor responde com chave RSA DER, certificado X.509
DER, assinatura e salt; o cliente exige pin exato do certificado.

O material assinado é `pk_server_DER || pk_client || client_id || salt`.
O digest SHA-256 é assinado com RSA-PSS, MGF1-SHA256 e salt PSS de 32 bytes.
Os registros de peers são assinados pelo servidor e vinculados ao cliente e ao
salt da sessão, com sequência administrativa anti-replay.

Para cada par, os dois lados usam o mesmo salt da sessão do servidor. O segredo
X25519 alimenta HKDF-Extract/HKDF-Expand; os rótulos `A2B` e `B2A` derivam
chaves AES distintas. O menor UUID binário é A.

Um frame E2E contém `nonce(12) || sender(16) || recipient(16) || seq(8) ||
ciphertext || tag(16)`. O nonce é `IV_base(4) || seq(8)`, o AAD é
`sender || recipient || seq`, e o limite do texto claro é 4096 bytes.
O servidor verifica framing, associação do remetente à conexão e destinatário
ativo, e encaminha os bytes intactos. O destinatário rejeita replay e só avança
o contador após autenticação AES-GCM; o servidor não confia em contadores E2E
sem poder validar a tag e nunca possui as chaves AES.

## Limites de segurança

- Instale o certificado por canal confiável; aceitar qualquer certificado recebido
  eliminaria a autenticação do servidor.
- O servidor é o diretório confiável de chaves. A assinatura protege anúncios em
  trânsito, mas não protege contra o próprio servidor malicioso.
- O protocolo não fornece autenticação de usuários, anonimato de metadados,
  persistência, ratchet ou zeroização garantida de memória.
- `server/server.key` é uma chave privada sem senha para uso local do trabalho.
  Proteja o arquivo e não o envie, publique ou faça commit.
- O cliente e servidor devem ser usados em um único event loop; escritas TCP
  do cliente são serializadas pelo adaptador.
