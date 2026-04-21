import { KeycloakOIDCAuth } from "./util.js";
import { config } from "./config.js";

export async function main(opts: { agg?: string, svc?: string, outputs?: string[] } = {}) {
  const aggId = opts.agg ?? config.activeAggregator;
  if (!aggId) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const agg = config.aggregators[aggId];
  if (!agg) throw new Error(`Aggregator "${aggId}" not found.`);

  const svcName = opts.svc ?? config.service.name;
  if (!svcName) throw new Error("No service name provided. Use --svc");

  const svc = agg.services[svcName];
  if (!svc) throw new Error(`Service "${svcName}" not found on Aggregator "${aggId}"`);

  const outputs = opts.outputs ?? svc.outputs;

  console.log("=== Initializing Keycloak Authentication ===");
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  console.log("🔐 Auth initialized successfully.");
  const umaFetch = auth.createUMAFetch();

  for (const output of outputs) {
    const OUTPUT_ENDPOINT = `${agg.id}/${svc.name}/${output}`;

    console.log(`\n=== Fetching output: ${output} ===`);
    console.log(`➡️  Endpoint: ${OUTPUT_ENDPOINT}\n`);

    try {
      const response = await umaFetch(OUTPUT_ENDPOINT, { method: "GET" });
      console.log(`📡 Response status: ${response.status}`);
      console.log("📄 Response body:\n");
      console.log(await response.text() || "(empty response)");
    } catch (err: any) {
      console.error(`\n❌ Failed to fetch output "${output}":`);
      console.error(err?.message || err);
    }
  }

  console.log("\n=== Done ===");
}