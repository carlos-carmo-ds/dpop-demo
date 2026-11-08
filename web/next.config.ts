import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Gera .next/standalone com só o necessário para rodar (imagem Docker pequena).
  output: "standalone",
};

export default nextConfig;
