import { KeycloakOIDCAuth } from "../util.js";

// Authz configuration
const USERNAME = "alice";
const PASSWORD = "alice";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "SsIyMNGjbKrbcJPHr8gWwc36DdqMGvvd";
const IDP = "http://localhost:8280";
const REALM = "quarkus";

// Aggregator
const AGGREGATOR = "https://aggregator.local:5443/419d851a-a6ab-4273-815d-0e59b6b44db4";
const PATH = "/transformations"; // "", "/services", "/transformations"

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