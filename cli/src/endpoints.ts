import { DataFactory } from "rdf-data-factory";
import { Parser, Store } from "n3";
import { config } from "./config.js";
import { AggregatorConfig, ServiceConfig } from "./config.template.js";
import { resolveService } from "./outputs.js";
import { KeycloakOIDCAuth } from "./util.js";

const df = new DataFactory();

export interface ServiceEndpoint {
  id: string;
  path: string;
  url: string;
}

export function serviceEndpointURL(aggregator: AggregatorConfig, service: ServiceConfig): string {
  return `${aggregator.id}${config.server.svc}/${service.name}`;
}

export async function fetchServiceEndpoints(opts: { agg?: string; svc?: string } = {}): Promise<{
  aggregator: AggregatorConfig;
  service: ServiceConfig;
  endpoints: ServiceEndpoint[];
}> {
  const { aggregator, service } = resolveService(opts);
  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  const umaFetch = auth.createUMAFetch();

  const serviceURL = serviceEndpointURL(aggregator, service);
  const response = await umaFetch(serviceURL, {
    method: "GET",
    headers: { accept: "text/turtle" },
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to fetch service description: HTTP ${response.status}: ${body}`);
  }

  return {
    aggregator,
    service,
    endpoints: parseServiceEndpoints(serviceURL, body),
  };
}

export function parseServiceEndpoints(serviceURL: string, turtle: string): ServiceEndpoint[] {
  const store = new Store(new Parser({ format: "text/turtle", baseIRI: serviceURL }).parse(turtle));
  const endpointURL = df.namedNode("http://www.w3.org/ns/dcat#endpointURL");
  const seen = new Set<string>();
  const endpoints: ServiceEndpoint[] = [];

  for (const candidate of store.getObjects(null, endpointURL, null)) {
    if (candidate.termType !== "NamedNode" || seen.has(candidate.value)) continue;
    seen.add(candidate.value);
    const path = endpointPath(serviceURL, candidate.value);
    endpoints.push({
      id: endpointID(path),
      path,
      url: candidate.value,
    });
  }

  return endpoints.sort((left, right) => left.id.localeCompare(right.id));
}

function endpointPath(serviceURL: string, endpointURLValue: string): string {
  const service = new URL(serviceURL);
  const endpoint = new URL(endpointURLValue);
  const servicePath = service.pathname.replace(/\/+$/, "");
  if (endpoint.pathname === servicePath) return "/";
  if (endpoint.pathname.startsWith(`${servicePath}/`)) {
    return endpoint.pathname.slice(servicePath.length);
  }
  return endpoint.pathname || "/";
}

function endpointID(path: string): string {
  const normalized = path.replace(/^\/+/, "").replace(/\/+$/, "");
  return normalized || "root";
}
