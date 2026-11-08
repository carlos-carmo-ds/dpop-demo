"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { handleCallback } from "@/lib/oidc";

export default function CallbackPage() {
  const router = useRouter();
  const started = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Em modo dev o React Strict Mode executa o efeito duas vezes; o code só pode ser trocado uma vez.
    if (started.current) return;
    started.current = true;

    handleCallback(window.location.href)
      .then(() => router.replace("/"))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, [router]);

  return (
    <div className="card">
      {error ? (
        <>
          <h2>Falha no login</h2>
          <p className="error">{error}</p>
          <a href="/">Voltar</a>
        </>
      ) : (
        <p>Trocando o authorization code por tokens DPoP…</p>
      )}
    </div>
  );
}
