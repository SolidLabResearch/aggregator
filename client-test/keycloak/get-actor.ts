import { KeycloakOIDCAuth } from "../util.js";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";
const USERNAME = "doctor@example.com";
const PASSWORD = "doctor";
const CLIENT_ID = "moveup-app";
const CLIENT_SECRET = "Yg8rGkQNQ4OqDh3AUR81EoSJtjPDXH4n";

const ACTOR_ENDPOINT = "http://aggregator.local/actors/7275e5fb-ffd5-4478-8e72-7770b411386c/fetch";


async function main() {
  console.log("=== Initializing Keycloak Authentication ===");

  const auth = new KeycloakOIDCAuth();
  await auth.init(IDP, REALM);
  await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

  
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  console.log("\n=== Fetching actor results ===");
  console.log(`➡️  Endpoint: ${ACTOR_ENDPOINT}\n`);

  try {
    const response = await umaFetch(ACTOR_ENDPOINT, { method: "GET" });

    console.log(`📡 Response status: ${response.status}`);
    console.log("📄 Response body:\n");

    const bodyText = await response.text();
    console.log(bodyText || "(empty response)");
  } catch (err: any) {
    console.error("\n❌ Failed to fetch actor result:");
    console.error(err?.message || err);
  }

  console.log("\n=== Done ===");
}

main().catch(console.error);