import { KeycloakOIDCAuth } from "../util.js";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";
const USERNAME = "patient0@example.com";
const PASSWORD = "1234";
const CLIENT_ID = "moveup-backend";
const CLIENT_SECRET = "GD7VyY29Eeim5BWfdTAFJ8FTDW7SeU2g";
const AGGREGATOR = "https://aggregator.local/18739d56-85ab-4837-a60c-e07df93d6fff";
const PATH = "/services"; // "", "/services", "/transformations"

async function main() {
  console.log("=== Initializing Keycloak Authentication ===");

  const auth = new KeycloakOIDCAuth();
  await auth.init(IDP, REALM);
  await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

  
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  console.log("\n=== Fetching configuration ===");
  const endpoint = AGGREGATOR + PATH;
  console.log(`➡️  Endpoint: ${endpoint}\n`);

  try {
    const response = await umaFetch(endpoint, { method: "GET" });

    console.log(`📡 Response status: ${response.status}`);
    console.log("📄 Response body:\n");

    const bodyText = await response.text();
    console.log(bodyText || "(empty response)");
  } catch (err: any) {
    console.error("\n❌ Failed to fetch available transformations:");
    console.error(err?.message || err);
  }

  console.log("\n=== Done ===");
}

main().catch(console.error);