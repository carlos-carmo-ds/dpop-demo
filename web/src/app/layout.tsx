import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DPoP Demo",
  description: "Next.js + .NET + Keycloak com tokens vinculados a DPoP",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
