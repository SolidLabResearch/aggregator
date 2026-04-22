import { KeycloakOIDCAuth } from "./util.js";
import { config } from "./config.js";

export async function main(opts: { agg?: string, public?: boolean } = {}) {
  let token: string | undefined;

  if (!opts.public) {
    console.log("=== Initializing Keycloak Authentication ===");

    const auth = new KeycloakOIDCAuth();
    await auth.init(config.auth.idp);
    await auth.login(
      config.auth.username,
      config.auth.password,
      config.auth.clientId,
      config.auth.clientSecret
    );

    token = await auth.getAccessToken();
    console.log("🔐 Auth initialized successfully.");
  } else {
    console.log("🌐 Public mode enabled — skipping authentication");
  }

  if (!opts.agg) {
    const REGISTRATION_ENDPOINT = config.server.host + config.server.reg;

    const response = await fetch(REGISTRATION_ENDPOINT, {
      method: "GET",
      headers: opts.public
        ? {} // no auth header
        : {
            "Authorization": `Bearer ${token}`,
          },
    });

    console.log(`📡 Response status: ${response.status}`);

    if (!response.ok) {
      const body = await response.text();
      console.log("📄 Response body:\n", body);
      return;
    }

    const data = await response.json();

    console.log(
      `List of available aggregators${opts.public ? " (public)" : ` for ${config.auth.username}`}:`
    );

    for (const id of data.aggregators) {
      console.log(`\t-> ${id}`);
    }
  }
}