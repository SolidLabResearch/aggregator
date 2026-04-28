import { KeycloakOIDCAuth } from "./util.js";
import { DataFactory } from "rdf-data-factory";
import { Writer } from "n3";
import { config, updateConfig } from "./config.js";
import { AggregatorConfig } from "./config.template.js";
import { format } from "path";

const df = new DataFactory();

export async function main(overrides?: {
  name?: string;
  tf?: string;
  params?: Record<string, string>;
  outputs?: string[];
  agg?: string;
}) {
  const aggId = overrides?.agg ?? config.activeAggregator;
  if (!aggId) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const agg = config.aggregators[aggId];
  if (!agg) throw new Error(`Aggregator "${aggId}" not found in config.`);

  const name   = overrides?.name    ?? config.service.name;
  const tf     = overrides?.tf      ?? config.service.tf;
  const params = overrides?.params  ?? config.service.params;
  const outputs = overrides?.outputs ?? config.service.outputs;

  const auth = new KeycloakOIDCAuth();
  await auth.init(config.auth.idp);
  await auth.login(config.auth.username, config.auth.password, config.auth.clientId, config.auth.clientSecret);
  const umaFetch = auth.createUMAFetch();

  console.log(`=== Parsing service request ===`);
  const desc = await parseServiceRequest(agg, name, tf, params);
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
        [name]: { name, tf, params, outputs }
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
  tf: string,
  params: Record<string, string>
): Promise<string> {
  const writer = new Writer({
    format: "turtle",
    prefixes: {
      trans: `${config.server.host}${config.server.tf}#`,
      fno: "https://w3id.org/function/ontology#",
      fnoc: "https://w3id.org/function/vocabulary/composition#",
      rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
      xsd: "http://www.w3.org/2001/XMLSchema#",
      agg: "https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#"
    }
  });

  const service = df.namedNode(`${agg.id}/${name}`);
  const fnoc = (local: string) => df.namedNode(`https://w3id.org/function/vocabulary/composition#${local}`);
  const aggNs = (local: string) => df.namedNode(`https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#${local}`);

  const paramBindings = Object.entries(params).map(([key, value]) =>
    writer.blank([
      { predicate: fnoc("boundToTerm"),   object: df.literal(value) },
      { predicate: fnoc("boundParameter"), object: df.namedNode(`${config.server.host}${config.server.tf}#${key}`) },
    ])
  );

  const application = writer.blank([
    { predicate: fnoc("applies"), object: df.namedNode(`${config.server.host}${config.server.tf}#${tf}`) },
    ...paramBindings.map(binding => ({ predicate: fnoc("parameterBinding"), object: binding })),
  ]);

  writer.addQuad(service, df.namedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), aggNs("Service"));
  writer.addQuad(service, aggNs("applies"), application);

  return new Promise((resolve, reject) => {
    writer.end((error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
}