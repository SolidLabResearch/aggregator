import { outputEndpoints, resolveService } from "./outputs.js";

export async function main(opts: { agg?: string; svc?: string } = {}) {
  const { aggregator, service } = resolveService(opts);
  const outputs = outputEndpoints(aggregator, service);

  if (outputs.length === 0) {
    console.log(`No output distributions are available for service "${service.name}".`);
    return;
  }

  console.log(`Outputs for service "${service.name}":`);
  for (const output of outputs) console.log(`${output.id}\t${output.url}`);
}
