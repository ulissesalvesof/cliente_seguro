# Explicação completa do projeto

## 1. Objetivo

Este projeto implementa um sistema de mensageria com criptografia ponta a ponta
(E2E). O cliente cifra a mensagem antes de enviá-la; o servidor encaminha os
bytes ao destinatário sem conhecer as chaves AES e sem decifrar o conteúdo.

O servidor ainda participa do estabelecimento de confiança: apresenta uma
identidade RSA autenticada por certificado, assina o handshake e distribui as
chaves públicas efêmeras dos clientes. O certificado precisa ser previamente
conhecido pelo cliente por um canal confiável.

O sistema contém o núcleo criptográfico, um cliente TCP, o servidor relay,
documentação e testes unitários e de integração. Não há interface gráfica nem
um chat interativo pronto para uso.

## 2. Componentes e arquivos

### `crypto_client.py`

Implementa o núcleo E2E:

- `Client` representa uma sessão de cliente. Cria um UUID v4 e um par de chaves
  X25519 efêmero. A chave privada permanece no cliente.
- `add_peer` instala um peer e deriva as chaves compartilhadas. Deve ser chamado
  somente depois de autenticar o anúncio recebido do servidor.
- `update_peer` substitui o estado criptográfico quando chega uma nova chave
  pública autenticada para uma sessão diferente. A substituição cria chaves,
  contador e nonce novos.
- `remove_peer` elimina o estado criptográfico daquele peer.
- `encrypt` gera um frame E2E; `decrypt` valida o frame e retorna o UUID do
  remetente e o conteúdo decifrado.
- `close` descarta as referências locais ao estado e à chave privada. Python
  não garante a limpeza física imediata dos bytes da memória.

Cada peer mantém suas próprias chaves AES de envio e recebimento, prefixos de
nonce e contadores. Os contadores começam em zero no envio e em -1 no
recebimento.

### `server_auth.py`

Contém as funções para:

- carregar certificados X.509 em DER ou PEM;
- validar o certificado recebido contra um certificado pinado;
- validar a assinatura RSA-PSS do handshake;
- construir, assinar e verificar anúncios e remoções de peers.

As mensagens de controle assinadas ficam vinculadas ao destinatário e ao salt
da sessão. Isso permite detectar alteração ou repetição de controles em trânsito.
Não protege contra o próprio servidor malicioso, que possui a chave privada RSA.

### `framing.py`

Implementa o framing TCP usado pelo cliente. Cada corpo é precedido por um
inteiro sem sinal de 4 bytes, em ordem big-endian, indicando o tamanho do corpo
(sem contar o próprio prefixo).

`read_frame` lê exatamente o prefixo e o corpo, aplica limite e timeout, e
transforma leitura incompleta em erro de protocolo. `pack_frame` e
`write_frame` constroem e enviam frames.

### `network_client.py`

Adapta o núcleo criptográfico à conexão TCP:

- `NetworkClient.connect` abre a conexão, registra o UUID e a chave X25519,
  interpreta a resposta do servidor e valida certificado e assinatura;
- `send` cifra a mensagem usando o peer e envia o frame;
- `receive_event` recebe um anúncio de peer, uma remoção ou uma mensagem E2E;
- anúncios e remoções só alteram o estado do cliente depois de validar a
  assinatura e a sequência administrativa;
- um lock serializa as escritas na conexão;
- `close` encerra a conexão e descarta o estado do cliente.

Uma aplicação de chat pode usar `receive_event` em uma tarefa assíncrona e
chamar `send` para transmitir mensagens. O projeto não inclui ainda essa
interface interativa.

### `server/servidor.py`

Implementa o servidor TCP:

- carrega a identidade RSA e o certificado ou os gera se ambos não existirem;
- limita o número de clientes ativos e verifica o tamanho dos frames;
- registra UUID e chave pública X25519;
- assina o handshake e os controles de atualização dos peers;
- envia anúncios de peers existentes e notifica os clientes conectados quando
  um peer entra ou sai;
- valida que o remetente do frame E2E corresponde ao cliente daquela conexão e
  que o destinatário está conectado;
- encaminha os frames E2E intactos, sem decifrá-los;
- remove a sessão e notifica os peers quando a conexão termina.

O servidor padrão escuta em `127.0.0.1:8888`. Variáveis de ambiente
`TP3_HOST` e `TP3_PORT` permitem configurar endereço e porta.

### `server/server.crt` e `server/server.key`

`server.crt` é o certificado público DER usado pelo cliente como pin.
`server.key` é a chave privada RSA correspondente, em PEM. A chave privada não
deve ser enviada aos clientes nem compartilhada. O `.gitignore` exclui
`server/server.key` do controle de versão, mas ainda é necessário verificar
manualmente o conteúdo de qualquer ZIP ou entrega.

Se somente um dos dois arquivos existir ou se a chave não corresponder ao
certificado, a inicialização do servidor falha em vez de substituir a
identidade silenciosamente.

### Testes, demo e documentação

- `tests/test_client.py`: testes do núcleo criptográfico, framing e handshake.
- `server/test_server.py`: testes de integração entre `NetworkClient` e o
  servidor real, iniciando-o em uma porta local temporária.
- `demo.py`: simulação criptográfica em memória, sem conexão TCP nem servidor.
- `README.md`: comandos gerais de instalação, execução e testes.
- `server/README.md`: operação do servidor.
- `INTEGRACAO.md`: especificação técnica do protocolo usado pelos dois lados.
- `requirements.txt`: dependência `cryptography==50.0.0`.

## 3. Criptografia E2E

### Identidades e chaves

Cada cliente usa:

- UUID v4, transmitido como 16 bytes;
- chave pública X25519 raw de 32 bytes;
- chave privada X25519 efêmera, que nunca é enviada ao servidor.

Quando A recebe a chave pública de B, calcula:

`Z_AB = X25519(sk_A, pk_B)`

B calcula o mesmo segredo usando sua chave privada e a chave pública de A.
O segredo `Z_AB` não é enviado pela rede.

### Derivação das chaves simétricas

Os dois clientes usam o mesmo `salt_srv` da época ativa do servidor:

1. `PRK = HMAC-SHA256(salt_srv, Z_AB)` (HKDF-Extract).
2. HKDF-Expand com `info = "A2B"` deriva uma chave AES de 16 bytes.
3. HKDF-Expand com `info = "B2A"` deriva outra chave AES de 16 bytes.
4. O UUID binário menor define A e o maior define B, de modo que ambos atribuam
   as mesmas chaves às direções de envio e recebimento.

As chaves de envio e recebimento são diferentes. As chaves são específicas para
o par de clientes; não existe uma chave AES global.

### Cifragem e autenticação da mensagem

O algoritmo é AES-128-GCM. Além de cifrar o texto, GCM produz uma tag de
autenticação de 16 bytes. Se o ciphertext, a tag ou os dados autenticados forem
alterados, a decifragem falha.

O limite de 4096 bytes refere-se ao texto em bytes, não ao número de caracteres.
Uma mensagem UTF-8 pode ocupar mais bytes que caracteres.

## 4. Formatos transmitidos

### Framing TCP

Todo frame TCP usa:

`comprimento(4 bytes, uint32 big-endian) || corpo`

TCP é um fluxo de bytes; não preserva os limites de mensagens. Uma chamada de
leitura pode receber parte de um frame ou mais de um. Por isso, o leitor consome
exatamente o prefixo e depois exatamente o tamanho indicado, validando-o antes
de ler o corpo.

### Registro e handshake

O cliente envia um frame de registro com 48 bytes:

`client_id(16) || pk_client_X25519(32)`

O corpo da resposta do servidor é:

`len(pk_server_DER)(4) || pk_server_DER || len(cert_DER)(4) || cert_DER || len(signature)(2) || signature || salt_srv(16)`

O cliente:

1. confere se o certificado recebido corresponde ao pin local;
2. verifica que a chave RSA informada corresponde à chave do certificado;
3. verifica a assinatura sobre o material:

   `pk_server_DER || pk_client_X25519 || client_id || salt_srv`

A assinatura usa SHA-256, RSA-PSS, MGF1 com SHA-256 e salt PSS de 32 bytes.
O certificado autoassinado não é confiável apenas por ter sido recebido: o pin
deve ser instalado por um canal confiável.

### Controles de peer

Os anúncios e remoções são frames separados, prefixados com o comprimento TCP.
O corpo contém:

- marcador `TP3C`;
- operação (`PEER_UP` ou `PEER_DOWN`);
- contador administrativo de 64 bits;
- UUID do peer;
- chave pública X25519 de 32 bytes quando a operação é `PEER_UP`;
- assinatura RSA-PSS do servidor.

A assinatura cobre também o UUID destinatário do controle e o salt da sessão.
O cliente verifica a assinatura e rejeita contadores repetidos ou antigos antes
de instalar ou remover um peer.

### Frame E2E

O corpo de cada frame E2E é:

`nonce(12) || sender_id(16) || recipient_id(16) || seq_no(8) || ciphertext || tag(16)`

Campos:

- nonce: prefixo IV de 4 bytes seguido do contador de 8 bytes big-endian;
- AAD: `sender_id || recipient_id || seq_no`;
- texto cifrado e tag: resultado da operação AES-GCM.

O cabeçalho tem 52 bytes; com a tag, o overhead mínimo é 68 bytes. Assim, um
texto vazio produz corpo de 68 bytes e um texto de 4096 bytes produz corpo de
4164 bytes. O prefixo TCP de 4 bytes fica fora desse tamanho.

## 5. Contadores, nonce e replay

Cada direção de cada par tem um contador próprio. O primeiro envio usa
`seq_no = 0`. O contador é incorporado ao nonce para evitar repetir o nonce com
a mesma chave AES.

No envio, o contador é reservado antes da cifragem. Se houver erro ao enviar,
o valor não deve ser reutilizado. O contador não volta a zero durante a mesma
sessão/chave; ao esgotar o espaço uint64, é necessário criar uma nova sessão.

No recebimento, o cliente rejeita `seq_no` menor ou igual ao último valor
autenticado. Ele só atualiza o contador e fixa o prefixo IV depois de a tag GCM
ser validada. Assim, uma mensagem adulterada não avança o estado.

O servidor não tem a chave AES e não consegue validar a tag. Por isso, ele não
deve avançar o estado de replay confiando apenas no contador: um frame forjado
com sequência alta poderia bloquear mensagens legítimas. A rejeição definitiva
de replay fica com o destinatário, que pode autenticar a mensagem.

## 6. Fluxo completo

1. O servidor carrega sua chave RSA e certificado.
2. O cliente cria UUID e chave X25519 e abre a conexão TCP.
3. O cliente envia o registro; o servidor responde com certificado, chave RSA
   pública, assinatura e salt.
4. O cliente verifica o pin e a assinatura antes de confiar na sessão.
5. O servidor envia controles assinados com os peers conectados.
6. O cliente valida cada controle e deriva as chaves E2E para os peers.
7. O remetente cifra a mensagem e envia o frame ao servidor.
8. O servidor valida framing, remetente e destinatário, e encaminha os bytes.
9. O destinatário verifica tamanho, IDs, sequência, nonce e tag GCM; só então
   disponibiliza o texto decifrado à aplicação.
10. Na desconexão, o servidor remove a sessão e notifica os demais clientes.

## 7. O que o servidor consegue ver

Embora não possa ler o conteúdo cifrado, o servidor vê metadados necessários
para encaminhar e validar frames:

- IDs do remetente e destinatário;
- tamanho do frame;
- contador e nonce;
- horários, endereços de rede e padrões de tráfego.

Portanto, E2E protege o conteúdo, mas não fornece anonimato nem esconde
metadados.

## 8. Segurança e limitações

- **Confiança no servidor:** controles assinados protegem anúncios contra
  adulteração por terceiros, mas o servidor é o diretório confiável. Um servidor
  malicioso pode anunciar uma chave falsa e assinar o anúncio.
- **Identidade de usuário:** UUID não é uma credencial. O protocolo não prova
  qual pessoa controla um cliente.
- **Pin:** a segurança do handshake depende da distribuição inicial confiável
  de `server.crt`.
- **Salt compartilhado:** as sessões ativas usam o mesmo salt para que clientes
  consigam derivar as mesmas chaves do par. O salt não é uma chave secreta; a
  proteção principal vem do segredo X25519.
- **Forward secrecy:** as chaves X25519 são efêmeras e novas em reconexões, mas
  não há ratchet. Capturar a chave privada efêmera de uma sessão ativa pode
  comprometer as mensagens daquela sessão.
- **Memória:** `close` descarta referências, mas Python não garante zeroização
  física dos bytes.
- **Persistência:** chaves e contadores não são persistidos; reconexões criam
  novas chaves e estado.
- **Concorrência:** o uso previsto é em um único event loop. Escritas do cliente
  são serializadas; não se deve acessar a mesma sessão simultaneamente de
  threads independentes.
- **Chave privada do servidor:** `server/server.key` não deve ser distribuída,
  publicada ou incluída em arquivos de entrega.

## 9. Instalação, execução e testes

Na raiz do projeto, no PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Executar a demo local em memória:

```powershell
python demo.py
```

Iniciar o servidor:

```powershell
python -m server.servidor
```

Executar todos os testes:

```powershell
python -m unittest discover -v
```

Os testes integrados iniciam um servidor em uma porta local temporária; não é
necessário iniciar o servidor manualmente antes de rodá-los.

## 10. O que os testes demonstram

Os testes unitários verificam:

- troca bidirecional e separação das chaves por direção;
- mensagens vazias, UTF-8 e no limite de 4096 bytes;
- rejeição de replay, adulteração, salt diferente, peer desconhecido e excesso
  de tamanho;
- ausência de avanço do estado quando a autenticação falha;
- reconexão com novas chaves;
- framing fragmentado, concatenado, incompleto, inválido e timeout;
- certificado pinado e assinatura correta/incorreta.

Os testes integrados verificam:

- handshake pinado e troca E2E nos dois sentidos;
- anúncio de peer e reconexão com o mesmo UUID, mas novas chaves;
- detecção de bitflip pelo destinatário;
- rejeição de replay sem envenenar o estado;
- encerramento de conexão após tentativa de falsificar o remetente;
- fechamento seguro diante de framing inválido.

Um teste automatizado não substitui a demonstração oral nem prova segurança
formal; ele registra que cenários específicos foram executados com sucesso.

## 11. Roteiro sugerido para apresentação

1. Explicar a arquitetura: clientes cifram e o servidor apenas encaminha.
2. Mostrar X25519/ECDH e explicar que o segredo compartilhado não trafega pela
   rede.
3. Explicar HKDF e a derivação de duas chaves AES direcionais.
4. Mostrar o frame, o nonce, o AAD e a tag do AES-GCM.
5. Demonstrar duas conexões e uma mensagem E2E no teste integrado.
6. Mostrar o teste de bitflip e explicar por que a tag é rejeitada.
7. Mostrar o replay e o framing inválido e explicar quem os rejeita.
8. Explicar o pin do certificado, a assinatura dos controles e a necessidade
   de proteger a chave privada.
9. Declarar os limites: metadados visíveis, confiança no servidor como diretório,
   ausência de autenticação humana, ratchet e interface interativa.

Os comandos principais para rodar a suíte integrada são:

```powershell
python -m unittest server.test_server -v
```
