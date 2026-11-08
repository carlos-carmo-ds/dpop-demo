"use client";

import { useEffect, useState } from "react";
import { attacks, callApi, getSession, login, logout, type ApiResult, type Session } from "@/lib/oidc";

const ATTACKS: { id: keyof typeof attacks; title: string; description: string }[] = [
  {
    id: "bearer",
    title: "Token roubado usado como Bearer",
    description: "Envia Authorization: Bearer <token>, sem prova DPoP.",
  },
  {
    id: "foreignKey",
    title: "Token roubado + chave do atacante",
    description: "Prova assinada por outra chave: o thumbprint não bate com o cnf.jkt do token.",
  },
  {
    id: "wrongUrl",
    title: "Prova criada para outra URL",
    description: "Prova com htu /api/admin enviada para /api/me.",
  },
  {
    id: "replay",
    title: "Replay da mesma prova",
    description: "A mesma prova (mesmo jti) é enviada duas vezes.",
  },
];

function errorMessage(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

function Result({ result }: { result?: ApiResult }) {
  if (!result) return null;
  return (
    <pre>
      <span className={`status ${result.ok ? "ok" : "bad"}`}>HTTP {result.status}</span>
      {result.note ? `\n${result.note}` : ""}
      {result.wwwAuthenticate ? `\nWWW-Authenticate: ${result.wwwAuthenticate}` : ""}
      {`\n${JSON.stringify(result.body, null, 2)}`}
    </pre>
  );
}

export default function Home() {
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState<Session | null>(null);
  const [results, setResults] = useState<Record<string, ApiResult>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setSession(getSession());
    setReady(true);
  }, []);

  async function run(id: string, action: () => Promise<ApiResult>) {
    setBusy(id);
    setError(null);
    try {
      const result = await action();
      setResults((previous) => ({ ...previous, [id]: result }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
      setSession(getSession());
    }
  }

  async function start(action: () => Promise<void>) {
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  if (!ready) return null;

  const cnf = session?.claims.cnf as { jkt?: string } | undefined;

  return (
    <>
      <h1>DPoP Demo</h1>
      <p className="muted">Next.js + API .NET + Keycloak, com tokens vinculados a uma chave do navegador.</p>

      {error && (
        <div className="card">
          <p className="error">{error}</p>
        </div>
      )}

      {!session ? (
        <div className="card">
          <h2>Não autenticado</h2>
          <p>
            Ao entrar, o navegador gera um par de chaves (ES256, privada não extraível), faz login com
            Authorization Code + PKCE e recebe um access token vinculado a essa chave.
          </p>
          <button onClick={() => start(login)}>Entrar com Keycloak</button>
        </div>
      ) : (
        <>
          <div className="card">
            <h2>Sessão</h2>
            <dl>
              <dt>Usuário</dt>
              <dd>{String(session.claims.preferred_username ?? "-")}</dd>
              <dt>Audience</dt>
              <dd>{JSON.stringify(session.claims.aud)}</dd>
              <dt>cnf.jkt</dt>
              <dd>
                <code>{cnf?.jkt ?? "ausente (token NÃO está vinculado a DPoP)"}</code>
              </dd>
              <dt>Expira em</dt>
              <dd>{new Date(session.expiresAt).toLocaleTimeString("pt-BR")}</dd>
            </dl>
            <button className="secondary" onClick={() => start(logout)}>
              Sair
            </button>
          </div>

          <div className="card">
            <h2>Chamada legítima</h2>
            <p className="muted">
              <code>Authorization: DPoP &lt;token&gt;</code> + header <code>DPoP</code> com uma prova nova assinada
              pela chave do navegador. Esperado: <span className="status ok">HTTP 200</span>.
            </p>
            <button disabled={busy !== null} onClick={() => run("legit", callApi)}>
              {busy === "legit" ? "Chamando…" : "GET /api/me"}
            </button>
            <Result result={results.legit} />
          </div>

          <div className="card">
            <h2>Simulações de ataque</h2>
            <p className="muted">
              Todas devem ser recusadas com <span className="status bad">HTTP 401</span>.
            </p>
            {ATTACKS.map((attack) => (
              <div className="attack" key={attack.id}>
                <div className="attack-head">
                  <div>
                    <strong>{attack.title}</strong>
                    <span className="muted">{attack.description}</span>
                  </div>
                  <button
                    className="secondary"
                    disabled={busy !== null}
                    onClick={() => run(attack.id, attacks[attack.id])}
                  >
                    {busy === attack.id ? "Executando…" : "Executar"}
                  </button>
                </div>
                <Result result={results[attack.id]} />
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}
