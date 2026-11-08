import { config } from "./config";
import { base64url, createDpopProof, generateDpopKeyPair, jwkThumbprint, randomString, sha256 } from "./dpop";
import { deleteKeyPair, loadKeyPair, saveKeyPair } from "./keystore";

/* ------------------------------------------------------------------ */
/* Tipos                                                               */
/* ------------------------------------------------------------------ */

type Discovery = {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint: string;
};

type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
};

type StoredSession = {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
};

export type Session = StoredSession & { claims: Record<string, unknown> };

export type ApiResult = {
  status: number;
  ok: boolean;
  body: unknown;
  wwwAuthenticate?: string;
  note?: string;
};

const LOGIN_KEY = "dpop-demo:login";
const SESSION_KEY = "dpop-demo:session";

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

let discoveryPromise: Promise<Discovery> | null = null;

function discovery(): Promise<Discovery> {
  discoveryPromise ??= fetch(`${config.issuer}/.well-known/openid-configuration`)
    .then((response) => {
      if (!response.ok) throw new Error(`Falha no discovery do Keycloak (HTTP ${response.status}).`);
      return response.json() as Promise<Discovery>;
    })
    .catch((error: unknown) => {
      discoveryPromise = null;
      throw error;
    });
  return discoveryPromise;
}

export function decodeJwt(jwt: string): Record<string, unknown> {
  const payload = jwt.split(".")[1] ?? "";
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

async function requireKeyPair(): Promise<CryptoKeyPair> {
  const keyPair = await loadKeyPair();
  if (!keyPair) throw new Error("Chave DPoP não encontrada. Faça login novamente.");
  return keyPair;
}

/**
 * Chama o token endpoint com uma prova DPoP.
 * Se o Keycloak exigir nonce (erro use_dpop_nonce), refaz a chamada uma vez com o nonce recebido.
 */
async function tokenRequest(
  keyPair: CryptoKeyPair,
  body: Record<string, string>,
  nonce?: string,
): Promise<TokenResponse> {
  const { token_endpoint } = await discovery();
  const proof = await createDpopProof(keyPair, { htm: "POST", htu: token_endpoint, nonce });

  const response = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: proof },
    body: new URLSearchParams(body),
  });
  const json = (await response.json()) as TokenResponse & { error?: string; error_description?: string };

  if (!response.ok) {
    const serverNonce = response.headers.get("DPoP-Nonce");
    if (json.error === "use_dpop_nonce" && serverNonce && !nonce) {
      return tokenRequest(keyPair, body, serverNonce);
    }
    throw new Error(`Token endpoint: ${json.error ?? response.status} ${json.error_description ?? ""}`.trim());
  }
  if (json.token_type?.toLowerCase() !== "dpop") {
    throw new Error(`Esperava token_type "DPoP", mas o Keycloak devolveu "${json.token_type}".`);
  }
  return json;
}

function saveSession(tokens: TokenResponse, previous?: StoredSession): void {
  const session: StoredSession = {
    accessToken: tokens.access_token,
    idToken: tokens.id_token ?? previous?.idToken,
    refreshToken: tokens.refresh_token ?? previous?.refreshToken,
    expiresAt: Date.now() + tokens.expires_in * 1000,
  };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function getSession(): Session | null {
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  const stored = JSON.parse(raw) as StoredSession;
  return { ...stored, claims: decodeJwt(stored.accessToken) };
}

/** Devolve um access token válido, renovando com o refresh token (também com DPoP) se expirou. */
async function currentAccessToken(keyPair: CryptoKeyPair): Promise<string> {
  const session = getSession();
  if (!session) throw new Error("Não autenticado.");
  if (Date.now() < session.expiresAt - 10_000) return session.accessToken;
  if (!session.refreshToken) throw new Error("Token expirado. Faça login novamente.");

  const tokens = await tokenRequest(keyPair, {
    grant_type: "refresh_token",
    refresh_token: session.refreshToken,
    client_id: config.clientId,
  });
  saveSession(tokens, session);
  return tokens.access_token;
}

/* ------------------------------------------------------------------ */
/* Login / callback / logout                                           */
/* ------------------------------------------------------------------ */

/** Inicia o Authorization Code + PKCE. Gera uma chave DPoP nova a cada login. */
export async function login(): Promise<void> {
  const { authorization_endpoint } = await discovery();

  const keyPair = await generateDpopKeyPair();
  await saveKeyPair(keyPair);

  const state = randomString();
  const nonce = randomString();
  const codeVerifier = randomString(32);
  sessionStorage.setItem(LOGIN_KEY, JSON.stringify({ state, nonce, codeVerifier }));

  const url = new URL(authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    nonce,
    code_challenge: base64url(await sha256(codeVerifier)),
    code_challenge_method: "S256",
    // Amarra o próprio authorization code a esta chave (RFC 9449, seção 10).
    dpop_jkt: await jwkThumbprint(keyPair.publicKey),
  }).toString();

  window.location.assign(url);
}

/** Processa o retorno do Keycloak em /callback e troca o code por tokens DPoP. */
export async function handleCallback(href: string): Promise<void> {
  const params = new URL(href).searchParams;
  const saved = JSON.parse(sessionStorage.getItem(LOGIN_KEY) ?? "null") as
    | { state: string; nonce: string; codeVerifier: string }
    | null;
  sessionStorage.removeItem(LOGIN_KEY);

  if (params.get("error")) {
    throw new Error(`${params.get("error")}: ${params.get("error_description") ?? ""}`);
  }
  if (!saved) throw new Error("Nenhum login em andamento.");
  if (params.get("state") !== saved.state) throw new Error("state inválido.");
  const code = params.get("code");
  if (!code) throw new Error("code ausente no retorno.");

  const keyPair = await requireKeyPair();
  const tokens = await tokenRequest(keyPair, {
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    code_verifier: saved.codeVerifier,
  });

  if (!tokens.id_token || decodeJwt(tokens.id_token).nonce !== saved.nonce) {
    throw new Error("nonce do id_token inválido.");
  }
  saveSession(tokens);
}

export async function logout(): Promise<void> {
  const session = getSession();
  sessionStorage.removeItem(SESSION_KEY);
  await deleteKeyPair();

  const { end_session_endpoint } = await discovery();
  const url = new URL(end_session_endpoint);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    post_logout_redirect_uri: config.postLogoutRedirectUri,
    ...(session?.idToken ? { id_token_hint: session.idToken } : {}),
  }).toString();
  window.location.assign(url);
}

/* ------------------------------------------------------------------ */
/* Chamadas à API                                                      */
/* ------------------------------------------------------------------ */

const ME_URL = () => new URL("/api/me", config.apiBaseUrl).toString();

async function send(url: string, headers: Record<string, string>): Promise<ApiResult> {
  const response = await fetch(url, { headers });
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    /* corpo não é JSON */
  }
  return {
    status: response.status,
    ok: response.ok,
    body,
    wwwAuthenticate: response.headers.get("WWW-Authenticate") ?? undefined,
  };
}

/** Chamada legítima: Authorization: DPoP <token> + prova nova assinada pela chave correta. */
export async function callApi(): Promise<ApiResult> {
  const keyPair = await requireKeyPair();
  const accessToken = await currentAccessToken(keyPair);
  const url = ME_URL();
  const proof = await createDpopProof(keyPair, { htm: "GET", htu: url, accessToken });
  return send(url, { Authorization: `DPoP ${accessToken}`, DPoP: proof });
}

/** Simulações de ataque: todas devem ser recusadas pela API com 401. */
export const attacks = {
  /** Token roubado usado como Bearer, sem prova. */
  async bearer(): Promise<ApiResult> {
    const accessToken = await currentAccessToken(await requireKeyPair());
    return send(ME_URL(), { Authorization: `Bearer ${accessToken}` });
  },

  /** Token roubado + prova assinada por OUTRA chave (a do atacante). */
  async foreignKey(): Promise<ApiResult> {
    const accessToken = await currentAccessToken(await requireKeyPair());
    const attackerKey = await generateDpopKeyPair();
    const proof = await createDpopProof(attackerKey, { htm: "GET", htu: ME_URL(), accessToken });
    return send(ME_URL(), { Authorization: `DPoP ${accessToken}`, DPoP: proof });
  },

  /** Prova válida, mas criada para outra URL. */
  async wrongUrl(): Promise<ApiResult> {
    const keyPair = await requireKeyPair();
    const accessToken = await currentAccessToken(keyPair);
    const otherUrl = new URL("/api/admin", config.apiBaseUrl).toString();
    const proof = await createDpopProof(keyPair, { htm: "GET", htu: otherUrl, accessToken });
    return send(ME_URL(), { Authorization: `DPoP ${accessToken}`, DPoP: proof });
  },

  /** A mesma prova enviada duas vezes (replay). */
  async replay(): Promise<ApiResult> {
    const keyPair = await requireKeyPair();
    const accessToken = await currentAccessToken(keyPair);
    const proof = await createDpopProof(keyPair, { htm: "GET", htu: ME_URL(), accessToken });
    const headers = { Authorization: `DPoP ${accessToken}`, DPoP: proof };
    const first = await send(ME_URL(), headers);
    const second = await send(ME_URL(), headers);
    return { ...second, note: `1ª chamada com a prova: HTTP ${first.status} · 2ª chamada (replay): HTTP ${second.status}` };
  },
};
