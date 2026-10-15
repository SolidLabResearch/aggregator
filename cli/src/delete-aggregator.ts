import { KeycloakOIDCAuth } from "./util.js";
import { config, updateConfig } from "./config.js";

/** Accepts either the stored aggregator URL or its bare ID. */
function resolveAggregatorKey(agg: string): string | undefined {
  if (config.aggregators[agg]) return agg;
  return Object.keys(config.aggregators).find((key) => key.replace(/\/+$/, "").endsWith(`/${agg}`));
}

export async function main(opts: { agg?: string } = {}) {
  const requested = opts.agg ?? config.activeAggregator;
  if (!requested) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const aggKey = resolveAggregatorKey(requested);
  if (!aggKey) throw new Error(`Aggregator "${requested}" not found in config.`);

  // The server identifies aggregators by the last path segment of their base URL.
  const aggregatorID = config.aggregators[aggKey].id.replace(/\/+$/, "").split("/").pop();
  const REGISTRATION = config.server.host + config.server.reg;

  console.log("=== Initializing Keycloak Authentication ===");
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  console.log("🔐 Auth initialized successfully.");

  console.log("\n=== Deleting aggregator ===");
  console.log(`➡️  Aggregator: ${aggKey}\n`);

  const response = await fetch(REGISTRATION, {
    method: "DELETE",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${await auth.getIdToken()}`,
    },
    body: JSON.stringify({ aggregator_id: aggregatorID }),
  });
  const body = await response.text();
  console.log(`📡 Response status: ${response.status}`);
  if (response.status === 404) {
    console.warn(`⚠️  Aggregator "${aggKey}" no longer exists on the server; removing it from the config.`);
  } else if (!response.ok) {
    throw new Error(`Failed to delete aggregator "${aggKey}": ${response.status}${body ? `, response: ${body}` : ""}`);
  }

  const { [aggKey]: _, ...remaining } = config.aggregators;
  const wasActive = config.activeAggregator === aggKey;
  updateConfig(
    { aggregators: remaining, ...(wasActive ? { activeAggregator: null } : {}) },
    ["aggregators"],
  );
  console.log(`✅ Aggregator "${aggKey}" deleted.`);
  if (wasActive) console.log("ℹ️  It was the active aggregator; run `agg set-active <id>` to pick another.");
}
