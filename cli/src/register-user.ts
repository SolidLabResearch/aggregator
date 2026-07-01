import { config, updateConfig } from "./config.js";
import { doDeviceCodeFlow } from "./device_code.js";
import { doTokenExchange } from "./token_exchange.js";

type RegisterdResponse = {
  aggregator: string,
  subject: string
}

export async function main(flow: string, opts: { setActive?: boolean } = {}) {
  // 1️⃣ Start registration flow
  let data: RegisterdResponse
  switch (flow) {
    case "device_code":
      data = await doDeviceCodeFlow();
      break;
    case "token_exchange":
      data = await doTokenExchange();
      break;
    default:
      throw new Error(`Unsupported registration flow: ${flow}`);
  }
  
  const aggId: string = data.aggregator;
  console.log("\n✅ Aggregator ready:", aggId);
  const aggregators = { ...config.aggregators };
  if (!aggregators[aggId]) {
    aggregators[aggId] = { id: aggId, services: {} };
  }

  updateConfig({
    aggregators,
    ...(opts.setActive ? { activeAggregator: aggId } : {}),
  });

  console.log(`✅ Aggregator "${aggId}" added to config.`);
  if (opts.setActive) console.log(`✅ Set as active aggregator.`);
}