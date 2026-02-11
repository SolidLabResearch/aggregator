import { KeycloakOIDCAuth } from "../util.js";

const IDP = "http://localhost:8280";
const REALM = "quarkus";
const USERNAME = "alice@example.com";
const PASSWORD = "alice";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "tVizN2ADzL4qQdaEkCi4Zxxbept2lvDs";

const AGGREGATOR = "https://aggregator.local/2a2b61ed-8976-4036-af9b-99b5925452a0"
const SERVICE_ENDPOINT = `${AGGREGATOR}/pacsoi-svc`;
const OUTPUT_ENDPOINT = `${SERVICE_ENDPOINT}/w-distribution`;

async function main() {
  console.log("=== Initializing Keycloak Authentication ===");

  const auth = new KeycloakOIDCAuth();
  await auth.init(IDP, REALM);
  await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

  
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  console.log("\n=== Fetching service config ===");
  console.log(`➡️  Endpoint: ${SERVICE_ENDPOINT}\n`);

  try {
    const response = await umaFetch(SERVICE_ENDPOINT, { method: "GET" });

    console.log(`📡 Response status: ${response.status}`);
    console.log("📄 Response body:\n");

    const bodyText = await response.text();
    console.log(bodyText || "(empty response)");
  } catch (err: any) {
    console.error("\n❌ Failed to fetch service config:");
    console.error(err?.message || err);
  }

  console.log("\n=== Fetching service results ===");
  console.log(`➡️  Endpoint: ${OUTPUT_ENDPOINT}\n`);

  try {
    const response = await umaFetch(OUTPUT_ENDPOINT, { method: "GET" });

    console.log(`📡 Response status: ${response.status}`);
    console.log("📄 Response body:\n");

    const bodyText = await response.text();
    console.log(bodyText || "(empty response)");
  } catch (err: any) {
    console.error("\n❌ Failed to fetch service result:");
    console.error(err?.message || err);
  }

  console.log("\n=== Done ===");
}

main().catch(console.error);
