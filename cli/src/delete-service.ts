import { KeycloakOIDCAuth } from "./util.js";
import { config, updateConfig } from "./config.js";

export async function main(opts: { agg?: string, name?: string } = {}) {
  const aggId = opts.agg ?? config.activeAggregator;
  if (!aggId) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const agg = config.aggregators[aggId];
  if (!agg) throw new Error(`Aggregator "${aggId}" not found.`);

  const svcName = opts.name ?? config.service.name;
  if (!svcName) throw new Error("No service name provided. Use --name or configure service.name.");

  const svc = agg.services[svcName];
  if (!svc) throw new Error(`Service "${svcName}" not found on Aggregator "${aggId}"`);

  const SERVICE_ENDPOINT = `${agg.id}${config.server.svc}/${svc.name}`;

  console.log("=== Initializing Keycloak Authentication ===");
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  console.log("\n=== Deleting service ===");
  console.log(`➡️  Endpoint: ${SERVICE_ENDPOINT}\n`);

  const response = await umaFetch(SERVICE_ENDPOINT, { method: "DELETE" });
  const body = await response.text();
  console.log(`📡 Response status: ${response.status}`);
  if (!response.ok) {
    throw new Error(`Failed to delete service "${svcName}": ${response.status}${body ? `, response: ${body}` : ""}`);
  }

  const { [svcName]: _, ...remainingServices } = agg.services;
  const updatedAgg = { ...agg, services: remainingServices };
  updateConfig({ aggregators: { ...config.aggregators, [aggId]: updatedAgg } });
  console.log(`✅ Service "${svcName}" deleted from aggregator "${aggId}".`);
}
