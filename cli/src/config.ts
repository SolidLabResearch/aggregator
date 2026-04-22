import { defaults, Config, AggregatorConfig } from "./config.template.js";
import { writeFileSync, existsSync, readFileSync } from "fs";
import { getConfigPath } from "./config-path.js";

const CONFIG_PATH = getConfigPath();

let userConfig: Partial<Config> = {};
if (existsSync(CONFIG_PATH)) {
  userConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
}

export const config: Config = deepMerge(defaults, userConfig) as Config;

function deepMerge(target: any, source: any, replaceKeys: string[] = []) {
  const result = { ...target };

  for (const key of Object.keys(source ?? {})) {
    if (replaceKeys.includes(key)) {
      result[key] = source[key];
      continue;
    }

    const sourceVal = source[key];

    if (
      sourceVal &&
      typeof sourceVal === "object" &&
      !Array.isArray(sourceVal)
    ) {
      result[key] = deepMerge(target[key] ?? {}, sourceVal, replaceKeys);
    } else {
      result[key] = sourceVal;
    }
  }

  return result;
}


export function updateConfig(updates: any, replaceKeys: string[] = []) {
  const current = existsSync(CONFIG_PATH)
    ? JSON.parse(readFileSync(CONFIG_PATH, "utf-8"))
    : {};

  const merged = deepMerge(current, updates, replaceKeys);

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