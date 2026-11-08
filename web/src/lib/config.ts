const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";

export const config = {
  issuer: process.env.NEXT_PUBLIC_KEYCLOAK_ISSUER ?? "http://localhost:8080/realms/dpop-demo",
  clientId: process.env.NEXT_PUBLIC_KEYCLOAK_CLIENT_ID ?? "dpop-web",
  redirectUri: `${appUrl}/callback`,
  postLogoutRedirectUri: `${appUrl}/`,
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:5080",
  scope: "openid profile email",
};
