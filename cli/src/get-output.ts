import { KeycloakOIDCAuth } from "./util.js";
import { config } from "./config.js";
import { outputEndpoints, resolveService } from "./outputs.js";

export async function main(opts: { output: string; agg?: string; svc?: string }) {
  const { aggregator, service } = resolveService(opts);
  const outputs = outputEndpoints(aggregator, service);
  const selected = outputs.find((candidate) => candidate.id === opts.output);
  if (!selected) {
    const available = outputs.map((candidate) => candidate.id).join(", ") || "none";
    throw new Error(`Output "${opts.output}" not found. Available outputs: ${available}.`);
  }

  console.log("=== Initializing Keycloak Authentication ===");
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  console.log(`\n=== Fetching output: ${selected.id} ===`);
  console.log(`➡️  Endpoint: ${selected.url}\n`);

  const response = await umaFetch(selected.url, { method: "GET" });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to fetch output "${selected.id}": HTTP ${response.status}: ${body}`);
  }
  console.log(body || "(empty response)");
}
