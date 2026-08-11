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
  .command("list")
  .description("List all available aggregators")
  .option("--all", "List all stored aggregators, without fetching from the server")
  .option("--public", "List all public aggregators on the server")
  .action(async (opts) => {
    if (opts.all) {
      console.log("List of stored aggregators:");
      for (const agg of Object.keys(config.aggregators))
        console.log(`\t-> ${agg}`);
      return
    }
    const { main } = await import("./get-aggregator.js");
    await main(opts);
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
  .option("--name <name>", "Service name")
  .option("--deployment-function <name>", "DeploymentFunction resource name")
  .option("--param <kv>", "Parameter predicate as key=value, repeatable", collect, [])
  .option("--agg <id>", "Aggregator ID to use instead of active")
  .action(async (opts) => {
    const { main } = await import("./create-service.js");
    await main({
      name: opts.name,
      deploymentFunction: opts.deploymentFunction,
      params:  opts.param?.length
        ? Object.fromEntries(opts.param.map(parseKeyValue))
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
  .command("delete-service")
  .description("Delete a service on the aggregator")
  .option("--agg <id>",   "Aggregator ID to use instead of active")
  .option("--name <name>", "Service name")
  .option("--svc <name>", "Deprecated alias for --name")
  .action(async (opts) => {
    const { main } = await import("./delete-service.js");
    await main({ agg: opts.agg, name: opts.name ?? opts.svc });
  });

program
  .command("list-outputs")
  .description("List the available dataset distribution endpoints")
  .option("--agg <id>",   "Aggregator ID to use instead of active")
  .option("--svc <name>", "Service name to use instead of configured default")
  .action(async (opts) => {
    const { main } = await import("./list-outputs.js");
    await main({ agg: opts.agg, svc: opts.svc });
  });

program
  .command("get-output <output>")
  .description("Fetch one output by dataset/distribution ID")
  .option("--agg <id>",   "Aggregator ID to use instead of active")
  .option("--svc <name>", "Service name to use instead of configured default")
  .action(async (output, opts) => {
    const { main } = await import("./get-output.js");
    await main({ output, agg: opts.agg, svc: opts.svc });
  });

program
  .command("list-endpoints")
  .description("List the available operational endpoints")
  .option("--agg <id>",   "Aggregator ID to use instead of active")
  .option("--svc <name>", "Service name to use instead of configured default")
  .action(async (opts) => {
    const { main } = await import("./list-endpoints.js");
    await main({ agg: opts.agg, svc: opts.svc });
  });

program
  .command("get-endpoint <endpoint>")
  .description("Fetch one operational endpoint by endpoint ID")
  .option("--agg <id>",   "Aggregator ID to use instead of active")
  .option("--svc <name>", "Service name to use instead of configured default")
  .action(async (endpoint, opts) => {
    const { main } = await import("./get-endpoint.js");
    await main({ endpoint, agg: opts.agg, svc: opts.svc });
  });

program
  .command("list-policies")
  .description("List active default ODRL policies")
  .option("--agg <id>", "Aggregator ID to use instead of active")
  .action(async (opts) => {
    const { listPolicies } = await import("./policies.js");
    await listPolicies({ agg: opts.agg });
  });

program
  .command("add-default-agreement <assignee>")
  .description("Add a default ODRL Agreement for an assignee ID")
  .option("--agg <id>", "Aggregator ID to use instead of active")
  .action(async (assignee: string, opts) => {
    const { addDefaultAgreement } = await import("./policies.js");
    await addDefaultAgreement({ assignee, agg: opts.agg });
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
  .command("reset")
  .description("Remove all aggregators and unset the active aggregator")
  .action(() => {
    updateConfig({ aggregators: {}, activeAggregator: null }, ["aggregators"]);
    console.log("✅ All aggregators removed and active aggregator unset.");
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

function parseKeyValue(value: string): [string, string] {
  const separator = value.indexOf("=");
  if (separator <= 0) {
    throw new Error(`Expected key=value, received "${value}".`);
  }
  return [value.slice(0, separator), value.slice(separator + 1)];
}

program.parse();
