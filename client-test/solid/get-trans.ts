import { SolidOIDCAuth } from "../util.js";

const WEB_ID = "http://localhost:3000/alice/profile/card#me";
const OIDC_ISSUER = "http://localhost:3000";
const EMAIL = "alice@example.org";
const PASSWORD = "abc123";

const CONFIG_ENDPOINT = "http://aggregator.local/config";

async function main() {
  console.log("=== Initializing Keycloak Authentication ===");

  const auth = new SolidOIDCAuth(
    WEB_ID,
    OIDC_ISSUER
  );
  await auth.init(EMAIL, PASSWORD);

  console.log(`=== Solid OIDC authentication initialized successfully\n`);

  const umaFetch = auth.createUMAFetch();

  console.log("\n=== Fetching available transformations ===");
  console.log(`➡️  Endpoint: ${CONFIG_ENDPOINT}\n`);

  try {
    const response = await umaFetch(CONFIG_ENDPOINT, { method: "GET" });

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