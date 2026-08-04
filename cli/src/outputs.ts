import { config } from "./config.js";
import { AggregatorConfig, ServiceConfig } from "./config.template.js";

export interface OutputEndpoint {
  id: string;
  datasetID: string;
  distributionID: string;
  url: string;
}

export function resolveService(opts: { agg?: string; svc?: string }): {
  aggregator: AggregatorConfig;
  service: ServiceConfig;
} {
  const aggregatorID = opts.agg ?? config.activeAggregator;
  if (!aggregatorID) throw new Error("No active aggregator. Use --agg or run `agg set-active`.");

  const aggregator = config.aggregators[aggregatorID];
  if (!aggregator) throw new Error(`Aggregator "${aggregatorID}" not found.`);

  const serviceName = opts.svc ?? config.service.name;
  if (!serviceName) throw new Error("No service name provided. Use --svc.");

  const service = aggregator.services[serviceName];
  if (!service) {
    throw new Error(`Service "${serviceName}" not found on Aggregator "${aggregatorID}".`);
  }
  return { aggregator, service };
}

export function outputEndpoints(aggregator: AggregatorConfig, service: ServiceConfig): OutputEndpoint[] {
  const endpoints: OutputEndpoint[] = [];
  for (const [datasetID, configured] of Object.entries(service.datasets)) {
    // Accept config files produced by older CLI versions.
    const distributions: Record<string, string> = typeof configured === "string"
      ? { default: configured }
      : configured;
    for (const [distributionID, accessURL] of Object.entries(distributions)) {
      const normalizedPath = accessURL.startsWith("/") ? accessURL : `/${accessURL}`;
      endpoints.push({
        id: `${datasetID}/${distributionID}`,
        datasetID,
        distributionID,
        url: /^https?:\/\//.test(accessURL)
          ? accessURL
          : `${aggregator.id}${config.server.svc}/${service.name}${normalizedPath}`,
      });
    }
  }
  return endpoints.sort((left, right) => left.id.localeCompare(right.id));
}
