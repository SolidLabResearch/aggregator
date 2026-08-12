import { randomUUID } from "node:crypto";
import { config } from "./config.js";
import { AggregatorConfig } from "./config.template.js";
import { KeycloakOIDCAuth } from "./util.js";

const ODRL_CONTEXT = "http://www.w3.org/ns/odrl.jsonld";

export async function listPolicies(opts: { agg?: string } = {}) {
  const aggregator = resolveAggregator(opts.agg);
  const umaFetch = await authenticatedFetch();
  const endpoint = policiesEndpoint(aggregator);
  const response = await umaFetch(endpoint, {
    method: "GET",
    headers: { accept: "application/ld+json" },
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to list policies: HTTP ${response.status}${body ? `: ${body}` : ""}`);
  }

  const policies = body ? JSON.parse(body) : [];
  console.log(JSON.stringify(policies, null, 2));
}

export async function addDefaultAgreement(opts: { assignee: string; agg?: string }) {
  const assignee = opts.assignee.trim();
  if (!assignee) throw new Error("Assignee ID must not be empty.");

  const aggregator = resolveAggregator(opts.agg);
  const umaFetch = await authenticatedFetch();
  const endpoint = policiesEndpoint(aggregator);
  const agreement = {
    "@context": ODRL_CONTEXT,
    "@type": "Agreement",
    uid: `urn:uuid:${randomUUID()}`,
    permission: [
      {
        "@type": "Permission",
        assignee,
      },
    ],
  };

  const response = await umaFetch(endpoint, {
    method: "POST",
    headers: {
      accept: "application/ld+json",
      "content-type": "application/ld+json",
    },
    body: JSON.stringify(agreement),
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to add default agreement: HTTP ${response.status}${body ? `: ${body}` : ""}`);
  }

  const location = response.headers.get("location");
  if (location) console.log(`✅ Default agreement created at ${location}`);
  else console.log("✅ Default agreement created.");
  if (body) console.log(JSON.stringify(JSON.parse(body), null, 2));
}

function resolveAggregator(id?: string): AggregatorConfig {
  const aggregatorID = id ?? config.activeAggregator;
  if (!aggregatorID) {
    throw new Error("No active aggregator. Use --agg or run `agg set-active`.");
  }
  const aggregator = config.aggregators[aggregatorID];
  if (!aggregator) throw new Error(`Aggregator "${aggregatorID}" not found in config.`);
  return aggregator;
}

export function policiesEndpoint(aggregator: AggregatorConfig): string {
  return `${aggregator.id.replace(/\/+$/, "")}/policies`;
}

export async function authenticatedFetch() {
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  return auth.createUMAFetch();
}
