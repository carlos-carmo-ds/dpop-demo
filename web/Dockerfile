# syntax=docker/dockerfile:1

# O build do Next gera só JavaScript, então roda na arquitetura da máquina de build
# e o resultado é copiado para a imagem final da arquitetura alvo (sem QEMU).
FROM --platform=$BUILDPLATFORM node:24-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Variáveis NEXT_PUBLIC_* são gravadas no bundle NO MOMENTO DO BUILD.
# Os padrões abaixo são as URLs do laboratório k3d; troque com --build-arg.
ARG NEXT_PUBLIC_KEYCLOAK_ISSUER=http://localhost:8080/realms/dpop-demo
ARG NEXT_PUBLIC_KEYCLOAK_CLIENT_ID=dpop-web
ARG NEXT_PUBLIC_APP_URL=http://dpop.localhost:9080
ARG NEXT_PUBLIC_API_BASE_URL=http://dpop.localhost:9080
ENV NEXT_PUBLIC_KEYCLOAK_ISSUER=$NEXT_PUBLIC_KEYCLOAK_ISSUER \
    NEXT_PUBLIC_KEYCLOAK_CLIENT_ID=$NEXT_PUBLIC_KEYCLOAK_CLIENT_ID \
    NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL \
    NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL

RUN npm run build

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static

# UID numérico (usuário "node" = 1000): com "runAsNonRoot" o Kubernetes só aceita a imagem
# se conseguir provar que o usuário não é root, e um nome ("node") não dá essa garantia.
USER 1000:1000
EXPOSE 3000
CMD ["node", "server.js"]
