import { KeycloakOIDCAuth } from "../util.js";

// Authz configuration
const USERNAME = "doctor";
const PASSWORD = "doctor";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "9GYhQo9FVtj5RMy4cteto8GgYtvdlvp1";
const IDP = "http://localhost:8280";
const REALM = "quarkus";

// Aggregator configuration
const AGGREGATOR = "https://aggregator.local:5443/7d540608-6e27-47d4-9bf7-0ac66205c78f"
const SERVICE_ENDPOINT = `${AGGREGATOR}/pacsoi-svc`;
const OUTPUT_ENDPOINT = `${SERVICE_ENDPOINT}/w-dist`;

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
