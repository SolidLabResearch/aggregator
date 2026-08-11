import { fetchServiceEndpoints } from "./endpoints.js";
import { KeycloakOIDCAuth } from "./util.js";
import { config } from "./config.js";

export async function main(opts: { endpoint: string; agg?: string; svc?: string }) {
  const { service, endpoints } = await fetchServiceEndpoints(opts);
  const selected = endpoints.find((candidate) => candidate.id === opts.endpoint);
  if (!selected) {
    const available = endpoints.map((candidate) => candidate.id).join(", ") || "none";
    throw new Error(`Endpoint "${opts.endpoint}" not found. Available endpoints: ${available}.`);
  }

  console.log("=== Initializing Keycloak Authentication ===");
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  console.log(`\n=== Fetching endpoint: ${selected.id} ===`);
  console.log(`➡️  Endpoint: ${selected.url}\n`);

  const response = await umaFetch(selected.url, { method: "GET" });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to fetch endpoint "${selected.id}": HTTP ${response.status}: ${body}`);
  }
  console.log(body || "(empty response)");
}
