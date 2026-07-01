import { config } from "./config.js";
import { KeycloakOIDCAuth } from "./util.js";

type RegisterdResponse = {
  aggregator: string,
  subject: string
}

export async function doTokenExchange(): Promise<RegisterdResponse> {
  console.log("Starting Token Exchange Flow...");
  const auth = new KeycloakOIDCAuth()
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);

  const registrationEndpoint = config.server.host + config.server.reg;
  const resp = await fetch(registrationEndpoint, {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${await auth.getAccessToken()}`
    },
    body: JSON.stringify({
      registration_type: "token_exchange",
      authorization_server: config.auth.uma,
    }),
  });

  if (resp.status === 201) {
    const data = (await resp.json());
    return data
  }

  if (resp.status === 400) {
    const errorText = await resp.text();
    throw new Error(`Token Exchange flow failed: ${errorText}`);
  }

  const errorText = await resp.text();
  throw new Error(`Unexpected error: ${resp.status} ${errorText}`);
}