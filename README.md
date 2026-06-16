# KeyVault

Um gestor de passwords que corre na tua própria máquina. Guarda as credenciais
cifradas, gera passwords fortes, e diz-te se alguma já apareceu em fugas de dados
conhecidas, sem nunca enviar a password para lado nenhum.

Não tem contas, nem nuvem, nem servidor remoto. O cofre é cifrado no cliente e o
que fica guardado é só texto cifrado.

Corre de duas formas, a partir do mesmo código:

- **App de ambiente de trabalho** (Electron) — janela própria, sem terminal, e dá `.exe`.
- **App web local** (Node) — abre no browser em `http://127.0.0.1:7700`.

## Funcionalidades

- Cofre cifrado com Argon2id e AES-256-GCM.
- Gerador de passwords com aleatoriedade criptográfica (comprimento, conjuntos de
  caracteres, excluir ambíguos).
- Medidor de força por entropia, em bits.
- Verificação de fugas contra a base Pwned Passwords do HIBP, uma password ou todas
  de uma vez.
- Exportar e importar o cofre como ficheiro `.json` cifrado (bom para backup).
- Procura, edição, eliminação. Copiar para a área de transferência com limpeza
  automática ao fim de 20 segundos. Bloqueio automático ao fim de 5 minutos parado.

## Primeira utilização

1. Abre a app (ver a seguir).
2. Define a master password. É ela que cifra tudo. Não é guardada e não pode ser
   recuperada, por isso escolhe uma que não percas.
3. Cria entradas com "Nova entrada". Em cada uma podes gerar uma password, ver a
   força, e verificar se já foi exposta.
4. No menu (`⋯`) tens "Verificar todas", "Exportar" e "Importar".

## Correr como app (Electron)

Precisas de [Node.js](https://nodejs.org) 18 ou superior. Na pasta do projeto:

```
npm install     # instala o Electron e as ferramentas (uma vez, precisa de internet)
npm run app     # abre a app
```

### Gerar o instalador `.exe`

```
npm run dist
```

Fica tudo em `dist/`:

- `KeyVault Setup x.y.z.exe` — instalador normal (NSIS).
- `KeyVault x.y.z.exe` — versão portable, corre sem instalar.

Na primeira vez, o `electron-builder` descarrega o Electron e o NSIS, por isso
precisa de internet. O `.exe` é construído na máquina Windows, que é o fluxo normal
do Electron. Se quiseres um ícone próprio, mete um `build/icon.ico` de 256×256 antes
de correr o `npm run dist`.

## Correr como app web local

O modo web não precisa de instalar nada além do Node:

```
node server.js
```

Depois abre `http://127.0.0.1:7700`. No Windows, o `iniciar.bat` faz o mesmo com
duplo-clique. Para mudar a porta: `set PORT=8080 && node server.js` (Windows) ou
`PORT=8080 node server.js` (Mac/Linux).

## Como funciona a cifra

A master password passa pelo **Argon2id** (RFC 9106, biblioteca `argon2id` da equipa
openpgpjs) e dá origem a uma chave **AES-256-GCM**. Parâmetros por omissão: 64 MiB de
memória, 3 passagens, 1 lane, salt aleatório de 16 bytes, IV aleatório de 12 bytes por
gravação.

O Argon2id aqui serve para derivar a *chave de cifra*, não para verificar a password.
A diferença é importante: não guardo nenhum hash da master password. O ficheiro do
cofre contém apenas isto:

```json
{
  "kdf": "argon2id",
  "argon2": { "memorySize": 65536, "passes": 3, "parallelism": 1, "tagLength": 32 },
  "salt": "...",
  "iv": "...",
  "ciphertext": "..."
}
```

A chave derivada vive só em memória e é recalculada a cada desbloqueio. Quando a
password está errada, é a etiqueta de autenticação do GCM que falha, não uma
comparação de hashes.

Cofres da versão anterior (PBKDF2) continuam a abrir e são migrados para Argon2id
automaticamente na primeira gravação.

## Como funciona a verificação de fugas

Usa a API Pwned Passwords do HIBP com k-anonymity:

1. Calcula o SHA-1 da password, localmente.
2. Envia só os 5 primeiros caracteres do hash à API.
3. A API devolve centenas de hashes que começam por esses 5 caracteres.
4. A comparação é feita aqui, na máquina.

A password e o resto do hash nunca saem. Na interface, a parte do hash que foi
enviada aparece destacada para tornar isto visível.

## Estrutura

```
keyvault/
├── main.js                 processo principal do Electron (janela + IPC)
├── preload.js              ponte segura entre a interface e o Node
├── server.js               servidor do modo web (sem dependências)
├── build-argon2.js         (re)gera o bundle do Argon2
├── iniciar.bat             atalho do modo web no Windows
├── package.json
└── public/
    ├── index.html
    ├── css/styles.css
    ├── vendor/
    │   └── argon2id.bundle.js   Argon2id com o Wasm embutido, funciona offline
    └── js/
        ├── crypto.js       Argon2id e AES-GCM (e PBKDF2 para cofres antigos)
        ├── storage.js      decide entre IPC (Electron) e HTTP (web)
        ├── pwned.js        verificação k-anonymity
        ├── generator.js    gerador de passwords
        ├── strength.js     força por entropia
        └── app.js          interface
```

## O que isto protege, e o que não protege

Protege:

- O cofre em repouso. Quem copie o `vault.json` sem a master password não lê nada.
- Contra password errada, o ficheiro simplesmente não decifra.
- Na verificação de fugas, a password fica na máquina.

Não protege:

- Contra malware ou keyloggers na própria máquina. Com o cofre aberto, a master
  password e os dados decifrados estão em memória, como em qualquer gestor.
- Não foi auditado. Para segredos de alto valor, usa antes um gestor com anos de
  revisão como o [Bitwarden](https://bitwarden.com),
  [KeePassXC](https://keepassxc.org) ou o 1Password.
- A área de transferência é limpa ao fim de 20 segundos, mas durante esse tempo
  outra aplicação pode lê-la.
- O modo web só escuta em `127.0.0.1` e não tem autenticação própria além da master
  password no cliente. Não o exponhas na rede sem TLS e controlo de acesso.

## Notas de desenvolvimento

O `public/vendor/argon2id.bundle.js` já vem pronto. Só precisas de o regenerar se
quiseres atualizar a versão da biblioteca:

```
npm install
npm run build:argon2
```

O script usa o esbuild para empacotar a lib `argon2id` num único ficheiro, com os
dois binários Wasm (SIMD e não-SIMD) embutidos em base64. É por isso que funciona
sem internet e sem passo de build do lado de quem usa.

## Créditos

- [argon2id](https://github.com/openpgpjs/argon2id) (openpgpjs), Argon2id em
  JS e WebAssembly.
- [Pwned Passwords](https://haveibeenpwned.com/Passwords) (Troy Hunt / HIBP),
  a base de fugas e o modelo de k-anonymity.

## Licença

Faz o que quiseres com o código. A biblioteca `argon2id` incluída é MIT.
