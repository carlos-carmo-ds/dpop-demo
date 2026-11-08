/**
 * DPoP (RFC 9449) usando apenas a WebCrypto API.
 * Sem dependências e sem imports: o mesmo código roda no navegador e no Node.js.
 */

const encoder = new TextEncoder();

export function base64url(input: ArrayBuffer | Uint8Array | string): string {
  const bytes =
    typeof input === "string" ? encoder.encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function sha256(value: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", encoder.encode(value));
}

export function randomString(byteLength = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/**
 * Gera o par de chaves do DPoP (EC P-256 / ES256).
 * extractable = false: a chave PRIVADA pode ser usada para assinar, mas nunca lida ou exportada.
 * (A chave pública é sempre exportável, por definição da WebCrypto.)
 */
export function generateDpopKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

/** Chave pública em JWK, só com os campos necessários (vai no header "jwk" da prova). */
export async function publicJwk(publicKey: CryptoKey): Promise<{ kty: string; crv: string; x: string; y: string }> {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", publicKey);
  if (!kty || !crv || !x || !y) throw new Error("Chave pública EC inválida.");
  return { kty, crv, x, y };
}

/**
 * Thumbprint da chave (RFC 7638): SHA-256 dos campos obrigatórios em ordem alfabética.
 * É esse valor que o Keycloak grava no token como cnf.jkt.
 */
export async function jwkThumbprint(publicKey: CryptoKey): Promise<string> {
  const { crv, kty, x, y } = await publicJwk(publicKey);
  return base64url(await sha256(JSON.stringify({ crv, kty, x, y })));
}

export type DpopProofInput = {
  /** Método HTTP da requisição (GET, POST...). */
  htm: string;
  /** URL da requisição. Query string e fragmento são removidos. */
  htu: string;
  /** Access token enviado junto (gera o claim "ath"). Não usado no token endpoint. */
  accessToken?: string;
  /** Nonce exigido pelo servidor (header DPoP-Nonce), se houver. */
  nonce?: string;
};

/** Cria a prova DPoP: um JWT novo, assinado pela chave privada, para UMA requisição. */
export async function createDpopProof(keyPair: CryptoKeyPair, input: DpopProofInput): Promise<string> {
  const htu = new URL(input.htu);
  htu.search = "";
  htu.hash = "";

  const header = { typ: "dpop+jwt", alg: "ES256", jwk: await publicJwk(keyPair.publicKey) };
  const payload: Record<string, string | number> = {
    jti: crypto.randomUUID(),
    htm: input.htm.toUpperCase(),
    htu: htu.toString(),
    iat: Math.floor(Date.now() / 1000),
  };
  if (input.accessToken) payload.ath = base64url(await sha256(input.accessToken));
  if (input.nonce) payload.nonce = input.nonce;

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  // A WebCrypto devolve a assinatura ECDSA no formato r||s, que é exatamente o que o JWS (ES256) espera.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64url(signature)}`;
}
