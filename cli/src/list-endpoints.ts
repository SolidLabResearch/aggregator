import { fetchServiceEndpoints } from "./endpoints.js";

export async function main(opts: { agg?: string; svc?: string } = {}) {
  const { service, endpoints } = await fetchServiceEndpoints(opts);

  if (endpoints.length === 0) {
    console.log(`No operational endpoints are available for service "${service.name}".`);
    return;
  }

  console.log(`Endpoints for service "${service.name}":`);
  for (const endpoint of endpoints) console.log(`${endpoint.id}\t${endpoint.url}`);
}
