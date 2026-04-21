import { defaults, Config, AggregatorConfig } from "./config.template.js";
import { writeFileSync, existsSync, readFileSync } from "fs";
import { getConfigPath } from "./config-path.js";

const CONFIG_PATH = getConfigPath();

let userConfig: Partial<Config> = {};
if (existsSync(CONFIG_PATH)) {
  userConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
}

export const config: Config = deepMerge(defaults, userConfig) as Config;

function deepMerge(target: any, source: any): any {
  const result = { ...target };
  for (const key of Object.keys(source ?? {})) {
    if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] ?? {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

export function updateConfig(updates: any) {
  const current = existsSync(CONFIG_PATH)
    ? JSON.parse(readFileSync(CONFIG_PATH, "utf-8"))
    : {};

  const merged = deepMerge(current, updates);

  writeFileSync(CONFIG_PATH, JSON.stringify(merged, null, 2));
}

export function getActiveAggregator(): AggregatorConfig {
  if (!config.activeAggregator) {
    throw new Error("No active aggregator set. Run `agg set-active <id>` or use --agg <id>.");
  }
  const agg = config.aggregators[config.activeAggregator];
  if (!agg) {
    throw new Error(`Aggregator "${config.activeAggregator}" not found in config.`);
  }
  return agg;
}