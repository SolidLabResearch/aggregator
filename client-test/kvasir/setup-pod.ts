import { createPolicies } from "./policies.js";
import { KvasirManagement } from "./management.js";

const POD_PROVIDER = "https://pacsoi-kvasir.faqir.org";
const AS_SERVER = "https://pacsoi-uma.faqir.org/uma"
const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";
const CLIENT_ID = "moveup-backend";
const CLIENT_SECRET = "GD7VyY29Eeim5BWfdTAFJ8FTDW7SeU2g";
const CLIENT_WEBID = "http://example.com/moveup-backend/webid"

const POD_NAME = "patient0";
const USER_ID = "d4c5e084-48ac-4c32-80e8-ec9276434bae";
const USERNAME = "patient0@example.com";
const PASSWORD = "patient0";
const DOCTOR_ID = "056e2d71-21aa-4528-a9f8-735ad76f0baa";

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
        assignee: `${IDP}/users/${USER_ID}`,
        assigner: CLIENT_WEBID,
        scopes: ["read", "write"],
        target: `${POD_PROVIDER}/${POD_NAME}/slices`,
        client: "moveup-backend",
      },
    ]);

    policyIds.push(...ownerPolicyIds);
    await kvasir.registerPolicies(ownerPolicyTurtle, CLIENT_WEBID);

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

    // grant owner access to slice
    const {
      turtle: slicePolicyTurtle,
      ids: slicePolicyIds,
    } = await createPolicies([
      {
        name: "SlicesOwnerDelete",
        assignee: `${IDP}/users/${USER_ID}`,
        assigner: CLIENT_WEBID,
        target: slice,
        scopes: ["delete"],
      },
      {
        name: "AggregatorDemoSliceOwnerReadWrite",
        assignee: `${IDP}/users/${USER_ID}`,
        assigner: CLIENT_WEBID,
        target: `${slice}/query`,
        scopes: ["read", "write"],
      },
      {
        name: "AggregatorDemoSliceDoctorRead",
        assignee: `${IDP}/users/${DOCTOR_ID}`,
        assigner: CLIENT_WEBID,
        target: `${slice}/query`,
        scopes: ["read"],
      }
    ]);

    policyIds.push(...slicePolicyIds);
    await kvasir.registerPolicies(slicePolicyTurtle, CLIENT_WEBID);

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
      await kvasir.deletePolicies(CLIENT_WEBID, policyIds);
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
  // Generate a random integer between 100 and 800
  const randomValue = Math.floor(Math.random() * (800 - 100 + 1)) + 100;
  // Fixed unit and current timestamp
  const unit = "steps per day";
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