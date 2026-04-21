#!/usr/bin/env node
import { Command } from "commander";
import { copyFileSync } from "fs";
import { resolve } from "path";
import { config, updateConfig } from "./config.js";
import { getConfigPath } from "./config-path.js";

const program = new Command();

program
  .name("agg")
  .description("CLI tool for interacting with an Aggregator Server")
  .version("1.0.0");

program
  .command("register-user")
  .description("Register a user via device flow")
  .option("--set-active", "Set the new aggregator as active")
  .action(async (opts) => {
    const { main } = await import("./register-user.js");
    await main({ setActive: opts.setActive });
  });

program
  .command("set-active <id>")
  .description("Set the active aggregator")
  .action((id: string) => {
    if (!config.aggregators[id]) {
      console.error(`❌ Aggregator "${id}" not found in config.`);
      process.exit(1);
    }
    updateConfig({ activeAggregator: id });
    console.log(`✅ Active aggregator set to "${id}".`);
  });

program
  .command("get-active")
  .description("Show the active aggregator")
  .action(() => {
    if (!config.activeAggregator) {
      console.log("No active aggregator set.");
    } else {
      console.log(`Active aggregator: ${config.activeAggregator}`);
      console.log(JSON.stringify(config.aggregators[config.activeAggregator], null, 2));
    }
  });

program
  .command("create-service")
  .description("Create a service on the aggregator")
  .option("--name <name>",       "Service name")
  .option("--tf <tf>",           "Transformation ID")
  .option("--outputs <outputs>", "Comma-separated outputs")
  .option("--param <kv>",        "Parameter as key=value, repeatable", collect, [])
  .option("--agg <id>",          "Aggregator ID to use instead of active")
  .action(async (opts) => {
    const { main } = await import("./create-service.js");
    await main({
      name:    opts.name,
      tf:      opts.tf,
      outputs: opts.outputs?.split(","),
      params:  opts.param?.length
        ? Object.fromEntries(opts.param.map((p: string) => p.split("=")))
        : undefined,
      agg: opts.agg,
    });
  });

program
  .command("get-service")
  .description("Fetch the service description")
  .option("--agg <id>",   "Aggregator ID to use instead of active")
  .option("--svc <name>", "Service name to use instead of active")
  .action(async (opts) => {
    const { main } = await import("./get-service.js");
    await main({ agg: opts.agg, svc: opts.svc });
  });

program
  .command("get-output")
  .description("Fetch service outputs")
  .option("--outputs <outputs>", "Comma-separated subset of outputs")
  .option("--agg <id>",          "Aggregator ID to use instead of active")
  .option("--svc <name>",        "Service name to use instead of active")
  .action(async (opts) => {
    const { main } = await import("./get-output.js");
    await main({ outputs: opts.outputs?.split(","), agg: opts.agg, svc: opts.svc });
  });

program
  .command("set-config <file>")
  .description("Load a JSON file as config")
  .action((file: string) => {
    const src = resolve(process.cwd(), file);
    const dest = getConfigPath();

    copyFileSync(src, dest);

    console.log(`✅ Config loaded from ${file}`);
  });

program
  .command("where-config")
  .description("Show config file location")
  .action(() => {
    console.log(getConfigPath());
  });

program
  .command("set-auth")
  .description("Set authentication configuration")
  .option("--username <username>", "Username")
  .option("--password <password>", "Password")
  .option("--client-id <id>", "Client ID")
  .option("--client-secret <secret>", "Client secret")
  .option("--idp <url>", "Identity provider URL")
  .option("--uma <url>", "UMA endpoint")
  .action((opts) => {
    const updates: any = {};

    if (opts.username) updates.username = opts.username;
    if (opts.password) updates.password = opts.password;
    if (opts.clientId) updates.clientId = opts.clientId;
    if (opts.clientSecret) updates.clientSecret = opts.clientSecret;
    if (opts.idp) updates.idp = opts.idp;
    if (opts.uma) updates.uma = opts.uma;

    if (Object.keys(updates).length === 0) {
      console.error("❌ No auth parameters provided.");
      process.exit(1);
    }

    updateConfig({
      auth: updates,
    });

    console.log("✅ Auth configuration updated.");
  });

function collect(val: string, acc: string[]) {
  acc.push(val);
  return acc;
}

program.parse();