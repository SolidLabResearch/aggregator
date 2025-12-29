import { KeycloakOIDCAuth } from "../util.js";

const ACTORS_ENDPOINT = "http://aggregator.local/config/8eef3823-5cbf-447c-abd9-9c848de3b402/actors";

const USERNAME = "doctor@example.com";
const PASSWORD = "doctor";
const CLIENT_ID = "moveup-app";
const CLIENT_SECRET = "Yg8rGkQNQ4OqDh3AUR81EoSJtjPDXH4n";

const ACTOR_ID = "comunica";
const DESCRIPTION = `
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:execution a fno:Execution ;
    fno:executes config:echo ;
`;

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";

const auth = new KeycloakOIDCAuth()
await auth.init(IDP, REALM)
await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);
const umaFetch = auth.createUMAFetch();

async function createActor(id: string, description: string) {
    console.log(`=== Creating actor at ${ACTORS_ENDPOINT} ===`);

    const actorRequest = {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id, description })
    };

    const response = await umaFetch(ACTORS_ENDPOINT, actorRequest);
    console.log(`=== Response status: ${response.status} ===`);

    if (response.status !== 202 && response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== Actor accepted ===`);
    const actor = await response.json();
    console.log(JSON.stringify(actor, null, 2));

    console.log(`=== Waiting for actor to become ready ===`);
    await waitForActorReady(actor.status);

    console.log(`🔧 Actor ${actor.id} endpoints:`);
    console.log(`configuration: ${actor.config}`);
    console.log(`endpoints: ${actor.endpoints}`);
}


async function waitForActorReady(statusUrl: string, intervalMs = 3000, timeoutMs = 60000): Promise<void> {
    const startTime = Date.now();

    while (true) {
        try {
            const response = await umaFetch(statusUrl, {
                headers: { Accept: "application/json" }
            });

            if (!response.ok) {
                throw new Error(`Status check failed: ${response.status}`);
            }

            const data = await response.json();

            if (data.ready === true) {
                console.log("✅ Actor is ready");
                return;
            } else {
                console.log("⏳ Actor not ready yet...");
            }
        } catch (err) {
            console.error("❌ Error checking status:", err);
        }

        // Check timeout
        if (Date.now() - startTime > timeoutMs) {
            throw new Error("Timeout waiting for actor to become ready");
        }

        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
}

async function main() {
    await createActor(ACTOR_ID, DESCRIPTION);
    //await waitForActorReady("http://aggregator.local/config/a6785d0b-c31c-48f4-bb93-6ba25f105bf0/actors/comunica/status");
}

main().catch(console.error);
