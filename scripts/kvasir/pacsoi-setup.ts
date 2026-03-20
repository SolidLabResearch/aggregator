import { createPolicies } from "./policies.js";
import { KvasirManagement } from "./management.js";
import readline from "readline";

const POD_URL = "http://localhost:8080/alice";
const AS_SERVER = "http://localhost:4000/uma"
const IDP = "http://localhost:8280";
const REALM = "quarkus";
const CLIENT_ID = "demo-client";
const CLIENT_UMA_ID = `http://example.com/id/${CLIENT_ID}`;
const CLIENT_SECRET = "oI6T6JNZR8ezbnWJafRIQtQrNIXCBqOh";

const USER_ID = "caf4f290-3646-4c5f-8d77-2509453e3732";
const USER_UMA_ID = `http://example.com/id/${USER_ID}`;
const USERNAME = "alice";
const PASSWORD = "alice";

const CONTEXT = {
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "schema": "http://schema.org/",
  "ex": "http://example.org/"
};

const SCHEMA = `
type Query {
  observations: [ex_Observation]!
}

type ex_Patient {
  id: ID!
}

type ex_Observation {
  id: ID!
  ex_value: Int!
  ex_unit: String!
  ex_timestamp: DateTime!
  forPatient: ex_Patient! @predicate(iri: "ex:hasObservation", reverse: true)
}

type Subscription {
  observationAdded: ex_Observation!
}

type Mutation {
  addObservation(obs: PatientObservationInput!): ID!
}

input ObservationInput @class(iri: "ex:Observation") {
  id: ID!
  ex_value: Int!
  ex_unit: String!
  ex_timestamp: DateTime!
}

input PatientObservationInput @class(iri: "ex:Patient") {
  id: ID!
  ex_hasObservation: ObservationInput!
}`;

const kvasir = new KvasirManagement(POD_URL, AS_SERVER);
await kvasir.init(IDP, REALM);
await kvasir.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

async function main() {
  // state
  const policyIds: string[] = [];
  const slices: Record<string, string> = {};
  let dataInterval: NodeJS.Timeout | null = null;

  try {
    console.log("▶ Delegating pod access control to UMA");
    await kvasir.delegatePodToUMA();

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
        scopes: ["read", "write", "delete"],
        target: POD_URL + "/slices",
        client: CLIENT_UMA_ID,
      },
    ]);

    policyIds.push(...ownerPolicyIds);
    await kvasir.registerPolicies(ownerPolicyTurtle);

    console.log("▶ Registering new slice…");

    // register slice
    const slice = await kvasir.registerSlice(
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
        name: "AggregatorDemoSliceOwnerQuery",
        assignee: USER_UMA_ID,
        assigner: USER_UMA_ID,
        target: `${slice}/query`,
        scopes: ["read", "write"],
      },
      {
        name: "AggregatorDemoSliceOwnerChanges",
        assignee: USER_UMA_ID,
        assigner: USER_UMA_ID,
        target: `${slice}/changes`,
        scopes: ["read", "write"],
      },
    ]);

    policyIds.push(...slicePolicyIds);
    await kvasir.registerPolicies(slicePolicyTurtle);

    // --- USER-DRIVEN DATA GENERATION ---
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    console.log("▶ Setup complete.");

    console.log("Press ENTER to generate and add one observation, or Ctrl+C to exit.\n");

    rl.on("line", async () => {
      try {
        const observation = generateObservation();
        await kvasir.addData(slice, CONTEXT, [observation]);
        console.log(`   ➝ Added observation ${observation.id}`);
        console.log("Press ENTER to add another observation…");
      } catch (err) {
        console.error("   ❌ Failed to add observation:", err);
      }
    });

    // Wait for termination signal
    await waitForExitSignal();
    rl.close();
  } catch (err) {
    console.error("❌ Error during setup:", err);
  } finally {
    // Wait for SIGINT or SIGTERM
    console.log("▶ Waiting to clean up setup (Ctrl+C)…\n");
    await waitForExitSignal();

    console.log("\n⏳ Cleaning up setup…");

    // Stop data generation
    if (dataInterval) {
      console.log("   ➝ Stopping data generation…");
      clearInterval(dataInterval);
    }

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

type KvasirValue =
  | string
  | number
  | boolean
  | null
  | { [key: string]: KvasirValue };

type KvasirInsert = Record<string, KvasirValue>;

function generateObservation(): KvasirInsert {
  // Generate a random integer between 60 and 100
  const randomValue = Math.floor(Math.random() * (100 - 60 + 1)) + 60;
  // Fixed unit and current timestamp
  const unit = "kg";
  const timestamp = new Date().toISOString();
  // Generate a unique observation ID
  const obsId = `ex:Observation${crypto.randomUUID()}`;

  return {
    "@type": "ex:Patient",
    id: USER_UMA_ID,
    ex_hasObservation: {
      "@type": "ex:Observation",
      id: obsId,
      ex_value: randomValue,
      ex_unit: unit,
      ex_timestamp: {
        "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
        "@value": timestamp
      },
    }
  }
}