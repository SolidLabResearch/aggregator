import { KeycloakOIDCAuth } from "./util.js";
import { DataFactory } from "rdf-data-factory";
import { Parser, Store, Writer } from "n3";
import { config, updateConfig } from "./config.js";
import { AggregatorConfig } from "./config.template.js";

const df = new DataFactory();

export async function main(overrides?: {
  name?: string;
  deploymentFunction?: string;
  params?: Record<string, string>;
  agg?: string;
}) {
  const aggId = overrides?.agg ?? config.activeAggregator;
  if (!aggId) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const agg = config.aggregators[aggId];
  if (!agg) throw new Error(`Aggregator "${aggId}" not found in config.`);

  const name   = overrides?.name    ?? config.service.name;
  const deploymentFunction = overrides?.deploymentFunction ?? config.service.deploymentFunction;
  const params = overrides?.params  ?? config.service.params;

  if (!name) throw new Error("No service name provided. Use --name or configure service.name.");
  if (!deploymentFunction) {
    throw new Error("No deployment function provided. Use --deployment-function or configure service.deploymentFunction.");
  }

  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  const umaFetch = auth.createUMAFetch();

  console.log(`=== Parsing service request ===`);
  const desc = await parseServiceRequest(agg, name, deploymentFunction, params, umaFetch);
  console.log(desc);

  console.log(`=== Creating service at ${agg.id}${config.server.svc} ===`);

  const response = await umaFetch(agg.id + config.server.svc, {
    method: "POST",
    headers: { "content-type": "text/turtle" },
    body: desc,
  });

  if (response.status === 202 || response.status === 201) {
    const serviceDescription = await response.text();
    const datasets = parseDatasetDistributions(serviceDescription);
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
  params: Record<string, string>,
  umaFetch: ReturnType<KeycloakOIDCAuth["createUMAFetch"]>
): Promise<string> {
  const serverHost = config.server.host.replace(/\/+$/, "");
  const catalogPath = config.server.deploymentCatalog.replace(/^\/+|\/+$/g, "");
  const deploymentURI = `${serverHost}/${catalogPath}/${encodeURIComponent(deploymentFunction)}`;
  const deploymentResponse = await umaFetch(deploymentURI, { headers: { accept: "text/turtle" } });
  if (!deploymentResponse.ok) {
    throw new Error(`Unable to load deployment function ${deploymentFunction}: ${deploymentResponse.status} ${await deploymentResponse.text()}`);
  }
  const deploymentStore = new Store(new Parser({ format: "text/turtle", baseIRI: deploymentURI }).parse(await deploymentResponse.text()));
  const writer = new Writer({
    format: "turtle",
    prefixes: {
      deploy: `${deploymentURI}#`,
      rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
      xsd: "http://www.w3.org/2001/XMLSchema#",
      aggr: "https://w3id.org/aggregator#"
    }
  });

  const service = df.namedNode(`${agg.id}${config.server.svc}/${name}`);
  const aggNs = (local: string) => df.namedNode(`https://w3id.org/aggregator#${local}`);

  writer.addQuad(service, df.namedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), aggNs("ServiceRequest"));
  writer.addQuad(service, aggNs("deploymentFunction"), df.namedNode(deploymentURI));
  for (const [key, value] of Object.entries(params)) {
    const predicateURI = /^https?:\/\//.test(key) ? key : `${deploymentURI}#${key}`;
    writer.addQuad(service, df.namedNode(predicateURI), parameterTerm(deploymentStore, predicateURI, value));
  }

  return new Promise((resolve, reject) => {
    writer.end((error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
}

function parameterTerm(store: Store, predicateURI: string, value: string) {
  const fnoPredicate = df.namedNode("https://w3id.org/function/ontology#predicate");
  const fnoType = df.namedNode("https://w3id.org/function/ontology#type");
  const parameter = store.getSubjects(fnoPredicate, df.namedNode(predicateURI), null)[0];
  if (!parameter) {
    throw new Error(`Deployment function has no parameter with predicate <${predicateURI}>.`);
  }
  const type = store.getObjects(parameter, fnoType, null)[0]?.value;
  if (!type || type === "http://www.w3.org/2001/XMLSchema#string") return df.literal(value);
  if (type === "http://www.w3.org/2001/XMLSchema#anyURI") return df.namedNode(value);
  if (type === "http://www.w3.org/2001/XMLSchema#boolean" && value !== "true" && value !== "false") {
    throw new Error(`Value for <${predicateURI}> must be true or false.`);
  }
  return df.literal(value, df.namedNode(type));
}

function parseDatasetDistributions(turtle: string): Record<string, Record<string, string>> {
  const store = new Store(new Parser({ format: "text/turtle" }).parse(turtle));
  const servesDataset = df.namedNode("http://www.w3.org/ns/dcat#servesDataset");
  const distribution = df.namedNode("http://www.w3.org/ns/dcat#distribution");
  const accessURL = df.namedNode("http://www.w3.org/ns/dcat#accessURL");
  const downloadURL = df.namedNode("http://www.w3.org/ns/dcat#downloadURL");
  const result: Record<string, Record<string, string>> = {};

  for (const dataset of store.getObjects(null, servesDataset, null)) {
    const datasetID = fragment(dataset.value);
    const distributions: Record<string, string> = {};
    for (const dist of store.getObjects(dataset, distribution, null)) {
      const distFragment = fragment(dist.value);
      const prefix = `${datasetID}-distribution-`;
      const distributionID = distFragment.startsWith(prefix) ? distFragment.slice(prefix.length) : distFragment;
      const url = store.getObjects(dist, accessURL, null)[0] ?? store.getObjects(dist, downloadURL, null)[0];
      if (url) distributions[distributionID] = url.value;
    }
    result[datasetID] = distributions;
  }
  return result;
}

function fragment(uri: string): string {
  const index = uri.lastIndexOf("#");
  return index >= 0 ? uri.slice(index + 1) : uri;
}
