import { KeycloakOIDCAuth } from "./util.js";
import { DataFactory } from "rdf-data-factory";
import { Writer } from "n3";
import { config, updateConfig } from "./config.js";
import { AggregatorConfig } from "./config.template.js";

const df = new DataFactory();

export async function main(overrides?: {
  name?: string;
  deploymentFunction?: string;
  params?: Record<string, string>;
  datasets?: Record<string, string>;
  agg?: string;
}) {
  const aggId = overrides?.agg ?? config.activeAggregator;
  if (!aggId) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const agg = config.aggregators[aggId];
  if (!agg) throw new Error(`Aggregator "${aggId}" not found in config.`);

  const name   = overrides?.name    ?? config.service.name;
  const deploymentFunction = overrides?.deploymentFunction ?? config.service.deploymentFunction;
  const params = overrides?.params  ?? config.service.params;
  const datasets = overrides?.datasets ?? config.service.datasets;

  if (!name) throw new Error("No service name provided. Use --name or configure service.name.");
  if (!deploymentFunction) {
    throw new Error("No deployment function provided. Use --deployment-function or configure service.deploymentFunction.");
  }

  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  const umaFetch = auth.createUMAFetch();

  console.log(`=== Parsing service request ===`);
  const desc = await parseServiceRequest(agg, name, deploymentFunction, params);
  console.log(desc);

  console.log(`=== Creating service at ${agg.id}${config.server.svc} ===`);

  const response = await umaFetch(agg.id + config.server.svc, {
    method: "POST",
    headers: { "content-type": "text/turtle" },
    body: desc,
  });

  if (response.status === 202 || response.status === 201) {
    const updatedAgg = {
      ...agg,
      services: {
        ...agg.services,
        [name]: { name, deploymentFunction, params, datasets }
      }
    };
    updateConfig({ aggregators: { ...config.aggregators, [aggId]: updatedAgg } });
    console.log(`✅ Service "${name}" added to aggregator "${aggId}".`);
  } else {
    throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
  }
}

async function parseServiceRequest(
  agg: AggregatorConfig,
  name: string,
  deploymentFunction: string,
  params: Record<string, string>
): Promise<string> {
  const writer = new Writer({
    format: "turtle",
    prefixes: {
      deploy: `${config.server.host}${config.server.deploymentCatalog}#`,
      rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
      xsd: "http://www.w3.org/2001/XMLSchema#",
      aggr: "https://w3id.org/aggregator#"
    }
  });

  const service = df.namedNode(`${agg.id}${config.server.svc}/${name}`);
  const aggNs = (local: string) => df.namedNode(`https://w3id.org/aggregator#${local}`);

  writer.addQuad(service, df.namedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), aggNs("ServiceRequest"));
  writer.addQuad(service, aggNs("deploymentFunction"), df.namedNode(`${config.server.host}${config.server.deploymentCatalog}#${deploymentFunction}`));
  for (const [key, value] of Object.entries(params)) {
    writer.addQuad(service, df.namedNode(`${config.server.host}${config.server.deploymentCatalog}#${key}`), df.literal(value));
  }

  return new Promise((resolve, reject) => {
    writer.end((error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
}
