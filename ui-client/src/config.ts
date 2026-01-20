export interface AppConfig {
  aggregatorBaseUrl: string;
  asDefaultUrl: string;
  redirectUriBase: string;
  keycloak: {
    clientId: string;
    url: string; 
    scope?: string;
  };
  user: {
    username: string,
    password: string,
  }
}

export const config: AppConfig = {
  aggregatorBaseUrl: "http://aggregator.local",
  asDefaultUrl: "http://wsl.local:4000/uma",
  redirectUriBase: "http://127.0.0.1:5173",
  keycloak: {
    clientId: "moveup-app",
    url: "https://pacsoi-idp.faqir.org/realms/kvasir",
    scope: "openid profile email offline_access",
  },
  user: {
    username: "alice",
    password: "7714",
  }
};
