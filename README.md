# DPoP Demo — Next.js + .NET + Keycloak

Exemplo de login com **Authorization Code + PKCE** e **tokens vinculados a DPoP** (RFC 9449):

- **web/** — Next.js 16. O navegador gera um par de chaves ES256 (privada **não extraível**,
  guardada no IndexedDB), faz login no Keycloak e assina uma prova DPoP para cada requisição.
- **api/** — ASP.NET Core (.NET 10). Valida o access token (assinatura, iss, aud, exp) e a
  prova DPoP (assinatura, htm, htu, iat, ath, cnf.jkt e replay de jti).
- **keycloak/** — realm `dpop-demo` pronto para importar.

```
Navegador (localhost:3000)          Keycloak (localhost:8080)          API .NET (localhost:5080)
  gera chave ES256
  /auth  (PKCE + dpop_jkt)  ───────►
  /token + header DPoP      ───────►  emite token com cnf.jkt
  GET /api/me
    Authorization: DPoP <token>
    DPoP: <prova nova>      ─────────────────────────────────────────► valida token + prova
```

## Pré-requisitos

- Keycloak rodando em `http://localhost:8080` (pasta `~/sources/keycloak`)
- Node.js 24+ → `brew install node`
- .NET 10 SDK → `brew install --cask dotnet-sdk`

## 1. Importar o realm no Keycloak

**Opção A — linha de comando** (usa o `--import-realm` do compose):

```bash
cp ~/sources/dpop-demo/keycloak/dpop-demo-realm.json ~/sources/keycloak/realms/
cd ~/sources/keycloak
docker compose restart keycloak
```

**Opção B — console:** http://localhost:8080 → menu de realms → *Create realm* →
*Resource file* → selecione `keycloak/dpop-demo-realm.json` → *Create*.

O realm cria:

| Item | Valor |
|---|---|
| Realm | `dpop-demo` |
| Client | `dpop-web` — público, PKCE S256, **Require DPoP bound tokens** ligado |
| Audience | mapper que adiciona `dpop-api` ao `aud` do access token |
| Usuário de teste | `alice` / `alice123` (troque se for manter o realm) |

## 2. Subir a API

```bash
cd ~/sources/dpop-demo/api
dotnet run
```

Escuta só em `http://localhost:5080` (loopback). Teste: `curl http://localhost:5080/api/health`

## 3. Subir o front

```bash
cd ~/sources/dpop-demo/web
npm install
npm run dev
```

Abra http://localhost:3000, clique em **Entrar com Keycloak** e use `alice` / `alice123`.
O servidor de dev escuta só em `127.0.0.1`.

## O que observar

- **Sessão:** o `cnf.jkt` do token é o thumbprint da chave gerada no navegador.
- **Chamada legítima:** `GET /api/me` → 200.
- **Simulações de ataque:** todas devem dar 401 — token como Bearer, prova com a chave de
  outra pessoa, prova para outra URL e replay da mesma prova.
- **DevTools → Network:** veja os headers `Authorization: DPoP ...` e `DPoP: ...` (cole a
  prova em https://jwt.io para ver `htm`, `htu`, `iat`, `jti`, `ath` e a `jwk`).
- **DevTools → Application → IndexedDB → dpop-demo:** a chave está lá como `CryptoKey`,
  e a privada aparece com `extractable: false`.
- **Terminal da API:** cada rejeição é registrada com o motivo.

## Estrutura

```
api/
  Program.cs                  JwtBearer + leitura do esquema "DPoP" + resposta 401 (RFC 9449)
  Dpop/DpopProofValidator.cs  validação da prova DPoP, passo a passo
  appsettings.json            Authority, Audience, URL pública, CORS
web/src/
  lib/dpop.ts                 geração de chave, thumbprint e prova DPoP (WebCrypto puro)
  lib/keystore.ts             guarda a chave no IndexedDB
  lib/oidc.ts                 login PKCE, callback, refresh, logout e chamadas à API
  app/page.tsx                tela principal e simulações de ataque
  app/callback/page.tsx       troca do code por tokens
keycloak/dpop-demo-realm.json realm para importar
```

## Deploy no k3d (GitOps)

A cada push na `main`, o GitHub Actions (`.github/workflows/ci.yml`) gera as imagens
`ghcr.io/<owner>/dpop-demo-api` e `dpop-demo-web` (amd64 + arm64) com tag `1.0.<run>`.
O deploy é feito pelo Argo CD a partir do repositório `dpop-demo-gitops` (Helm chart).

```
Navegador ──► http://dpop.localhost:9080/      → Traefik → web (Next.js)
          ──► http://dpop.localhost:9080/api/* → Traefik → api (.NET)
          ──► http://localhost:8080            → Keycloak (docker compose)
api (pod) ──► http://host.k3d.internal:8080    → Keycloak (discovery/JWKS)
```

- `Keycloak:MetadataAddress` (opcional) separa o endereço de onde a API busca o discovery/JWKS
  do issuer esperado (`Keycloak:Authority`). Requer `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` no Keycloak.
- As variáveis `NEXT_PUBLIC_*` são gravadas no bundle **no build** da imagem (build args no
  `web/Dockerfile`, com padrões para o laboratório).

## Antes de levar para produção

Este exemplo é didático. Em produção:

- Use **HTTPS** em tudo (e `RequireHttpsMetadata: true` na API).
- Use um **cache distribuído** (ex.: Redis) para os `jti`, se houver mais de uma instância da API.
- Configure `Dpop:PublicBaseUrl` com a URL pública real quando houver proxy/gateway na frente.
- Considere o padrão **BFF** (tokens no servidor, cookie de sessão no navegador) se o front
  for exposto a risco alto de XSS — DPoP limita o uso de token roubado, mas não impede que
  um XSS ativo use a chave enquanto a página está aberta.
- Prefira bibliotecas mantidas (`oauth4webapi`, `oidc-client-ts`) no lugar do código manual
  de `lib/oidc.ts`, que aqui está explícito para fins de estudo.
