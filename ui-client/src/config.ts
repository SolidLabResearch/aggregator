export interface AppConfig {
  aggregatorBaseUrl: string;
  asDefaultUrl: string;
  redirectUriBase: string;
  keycloak: {
    clientId: string;
    url: string; 
    redirectUri: string; 
    scope?: string;
  };
}

export const config: AppConfig = {
  aggregatorBaseUrl: "http://aggregator.local",
  asDefaultUrl: "http://wsl.local:4000/uma",
  redirectUriBase: "http://127.0.0.1:5173",
  keycloak: {
    clientId: "moveup-app",
    url: "https://pacsoi-idp.faqir.org/realms/kvasir",
    redirectUri: "http://localhost:5173/callback",
    scope: "openid profile email offline_access",
  },
};
