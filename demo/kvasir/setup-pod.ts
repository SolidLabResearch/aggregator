import { createPolicies } from "./policies.js";
import { KvasirManagement } from "./management.js";

const POD_PROVIDER = "http://localhost:8080";
const AS_SERVER = "http://localhost:4000/uma"
const IDP = "http://localhost:8280";
const REALM = "quarkus";
const CLIENT_ID = "demo-client";
const CLIENT_UMA_ID = `http://example.com/${CLIENT_ID}`;
const CLIENT_SECRET = "tVizN2ADzL4qQdaEkCi4Zxxbept2lvDs";

const POD_NAME = "alice";
const USER_ID = "bf53d8c4-cf4f-4847-9173-dcb17dd936df";
const USER_UMA_ID = `http://example.com/${USER_ID}`;
const USERNAME = "alice@example.com";
const PASSWORD = "alice";
const DOCTOR_ID = "257476d4-7b52-4dd1-a3ba-d57021e5d057";
const DOCTOR_UMA_ID = `http://example.com/${DOCTOR_ID}`

const CONTEXT = {
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "schema": "http://schema.org/",
  "ex": "http://example.org/"
}

const SCHEMA = `
type Query {
  observations: [ex_Observation]!
  observation(id: ID!): ex_Observation
}

type ex_Observation {
  id: ID!
  ex_value: Int!
  ex_unit: String!
  ex_timestamp: DateTime!
}

type Mutation {
  add(obs: [ObservationInput!]!): ID!
}

type Subscription {
  observationAdded: ex_Observation!
}
  
input ObservationInput @class(iri: "ex:Observation") {
  id: ID!
  ex_value: Int!
  ex_unit: String!
  ex_timestamp: DateTime!
}`

const kvasir = new KvasirManagement(POD_PROVIDER, AS_SERVER);
await kvasir.init(IDP, REALM);
await kvasir.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

async function test() {
  // await readPolicies({ asServer: AS_SERVER, assigner: CLIENT_WEBID});
  // const policyIds = [ "http://example.org/41da2792-e325-4463-bd3d-fcd833fc869b#slicesPolicy" ];
  // await deletePolicies({ asServer: AS_SERVER, assigner: CLIENT_WEBID, policyIds });
  // await readPolicies({ asServer: AS_SERVER, assigner: CLIENT_WEBID});
}

async function main() {
  // state
  const policyIds: string[] = [];
  const slices: Record<string, string> = {};

  try {
    console.log("▶ Creating slice-management policy for owner…");

    // enable owner to create slices
    const {
      turtle: ownerPolicyTurtle,
      ids: ownerPolicyIds,
    } = await createPolicies([
      {
        name: "owner_slice_management",
        assignee: USER_UMA_ID,
        assigner: USER_UMA_ID,
        scopes: ["read", "write"],
        target: `${POD_PROVIDER}/${POD_NAME}/slices`,
        client: CLIENT_UMA_ID,
      },
    ]);

    policyIds.push(...ownerPolicyIds);
    await kvasir.registerPolicies(ownerPolicyTurtle);

    console.log("▶ Registering new slice…");

    // register slice
    const slice = await kvasir.registerSlice(
      POD_NAME,
      CONTEXT,
      SCHEMA,
      "AggregatorDemoSlice",
      "Slice for aggregator demo"
    );

    slices["AggregatorDemoSlice"] = slice;

    console.log(`   ➝ Slice created: ${slice}`);

    console.log("▶ Granting owner access to slice…");

    // grant owner & doctor access to slice
    const {
      turtle: slicePolicyTurtle,
      ids: slicePolicyIds,
    } = await createPolicies([
      {
        name: "SlicesOwnerDelete",
        assignee: USER_UMA_ID,
        assigner: USER_UMA_ID,
        target: slice,
        scopes: ["delete"],
      },
      {
        name: "AggregatorDemoSliceOwnerReadWrite",
        assignee: USER_UMA_ID,
        assigner: USER_UMA_ID,
        target: `${slice}/query`,
        scopes: ["read", "write"],
      },
      {
        name: "AggregatorDemoSliceDoctorRead",
        assignee: DOCTOR_UMA_ID,
        assigner: DOCTOR_UMA_ID,
        target: `${slice}/query`,
        scopes: ["read"],
      }
    ]);

    policyIds.push(...slicePolicyIds);
    await kvasir.registerPolicies(slicePolicyTurtle);

    // Adding dummy data
    await kvasir.addData(slice, CONTEXT, "obs", generateObservation());
    await kvasir.addData(slice, CONTEXT, "obs", generateObservation());
    await kvasir.addData(slice, CONTEXT, "obs", generateObservation());
    await kvasir.addData(slice, CONTEXT, "obs", generateObservation());

    console.log("▶ Setup complete.");
    console.log("▶ Waiting for termination signal (Ctrl+C)…\n");

    // Wait for SIGINT or SIGTERM
    await waitForExitSignal();

  } catch (err) {
    console.error("❌ Error during setup:", err);
  } finally {
    console.log("\n⏳ Cleaning up setup…");

    // delete slices
    for (const slice of Object.values(slices)) {
      try {
        console.log(`   ➝ Deleting slice: ${slice}`);
        await kvasir.deleteSlice(slice);
      } catch (err) {
        console.error(`   ❌ Failed to delete slice ${slice}:`, err);
      }
    }

    // delete policies
    try {
      console.log("   ➝ Deleting policies…");
      await kvasir.deletePolicies(policyIds);
    } catch (err) {
      console.error("   ❌ Failed to delete policies:", err);
    }

    console.log("✔ Cleanup complete. Exiting.");
  }
}

main().catch((err) => {
  console.error("❌ Fatal error:", err);
  process.exit(1);
});

function waitForExitSignal(): Promise<void> {
  return new Promise(resolve => {
    const interval = setInterval(() => {}, 1 << 30); // very long interval, keeps event loop alive

    const handler = () => {
      clearInterval(interval); // allow process to exit
      process.off("SIGINT", handler);
      process.off("SIGTERM", handler);
      resolve();
    };

    process.on("SIGINT", handler);
    process.on("SIGTERM", handler);
  });
}

function generateObservation(): Record<string, string> {
  // Generate a random integer between 60 and 100
  const randomValue = Math.floor(Math.random() * (100 - 60 + 1)) + 60;
  // Fixed unit and current timestamp
  const unit = "kg";
  const timestamp = new Date().toISOString();
  // Generate a unique observation ID
  const obsId = `ex:Observation${crypto.randomUUID()}`;

  return {
    id: obsId,
    ex_value: randomValue.toString(),
    ex_unit: unit,
    ex_timestamp: timestamp,
  }
}