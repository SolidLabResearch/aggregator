import { KeycloakOIDCAuth } from "../util.js";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";
const USERNAME = "patient0@example.com";
const PASSWORD = "1234";
const CLIENT_ID = "moveup-backend";
const CLIENT_SECRET = "GD7VyY29Eeim5BWfdTAFJ8FTDW7SeU2g";

const SERVICE_ENDPOINT = "https://aggregator.local/15359d0a-df50-4083-8c88-b457ec7d2399/get-example-service";
const OUTPUT_ENDPOINT = "https://aggregator.local/15359d0a-df50-4083-8c88-b457ec7d2399/get-example-service/resp";

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
