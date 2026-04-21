import { homedir } from "os";
import { resolve, dirname } from "path";
import { existsSync, mkdirSync } from "fs";

function ensureDir(path: string) {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

export function getConfigPath(): string {
  // 1. Explicit override
  if (process.env.AGG_CONFIG) {
    return resolve(process.env.AGG_CONFIG);
  }

  // 2. XDG (Linux/macOS modern standard)
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg) {
    const dir = resolve(xdg, "agg");
    ensureDir(dir);
    return resolve(dir, "config.json");
  }

  // 3. Fallback
  const dir = resolve(homedir(), ".agg");
  ensureDir(dir);
  return resolve(dir, "config.json");
}
