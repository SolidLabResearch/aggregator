import { createParser } from "eventsource-parser";
import { KeycloakOIDCAuth } from "../util.js";

const ACTORS_ENDPOINT = "http://aggregator.local/config/7dbd3102-2207-4f2d-aa01-b1b4c7e8b76a/actors";

const USERNAME = "doctor@example.com";
const PASSWORD = "doctor";
const CLIENT_ID = "moveup-app";
const CLIENT_SECRET = "Yg8rGkQNQ4OqDh3AUR81EoSJtjPDXH4n";

const ACTOR_ID = "echo";
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

    // console.log(`=== Waiting for actor to become ready ===`);

    // Listen to actor status SSE endpoint
    // await waitForActorReady(actor.status);

    console.log(`🔧 Actor ${actor.id} endpoints:`);
    console.log(`configuration: ${actor.config}`);
    console.log(`endpoints: ${actor.endpoints}`);
}

async function waitForActorReady(statusUrl: string): Promise<void> {
    const response = await umaFetch(statusUrl, {
        headers: { Accept: "text/event-stream" }
    });

    if (!response.ok || !response.body) {
        throw new Error(`Failed to connect to SSE at ${statusUrl}`);
    }

    console.log("CONTENT TYPE: ", response.headers.get("Content-Type"));

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    return new Promise<void>((resolve, reject) => {
        let doneReading = false;

        const parser = createParser({
            onEvent(event) {
                const data = JSON.parse(event.data);

                if (data.type === "ready") {
                    console.log("✅ Actor is ready:", data.message || "");
                    doneReading = true;
                    reader.cancel();        
                    resolve();
                } else if (data.type === "error") {
                    console.error("❌ Actor failed:", data.message || "");
                    doneReading = true;
                    reader.cancel();        
                    reject(new Error(data.message || "Actor error"));
                } else {
                    console.log(`ℹ️ Event [${data.type}]: ${data.message || ""}`);
                }
            }
        });

        (async () => {
            try {
                while (true) {
                    const { value, done } = await reader.read();
                    if (done || doneReading) break;
                    parser.feed(decoder.decode(value));
                }
            } catch (err) {
                reject(err);
            }
        })();
    });
}

async function main() {
    await createActor(ACTOR_ID, DESCRIPTION);
    //await waitForActorReady("http://aggregator.local/config/doctor/actors/echo/status")
}

main().catch(console.error);
