const REGISTER_ENDPOINT = "http://aggregator.local/register";

const ID = "http://wsl.local:3000/doctor/profile/card#me";
const SECRET = "doctor";
const ISSUER = "http://wsl.local:3000/doctor";
const NAME = "doctor";
const AS_URL = "http://wsl.local:4000/uma";

const ACTOR_ID = "echo";
const DESCRIPTION = `
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:execution a fno:Execution ;
    fno:executes config:echo ;
`;

async function register(id: string, secret: string, issuer: string, name: string, as_url: string): Promise<string> {
    console.log(`=== Registering user at ${REGISTER_ENDPOINT} ===`);
    const registerRequest = {
        method: "POST",
        headers: {
            "content-type": "application/json"
        },
        body: JSON.stringify({
            id,
            secret,
            issuer,
            name,
            as_url
        })
    };
    const response = await fetch(REGISTER_ENDPOINT, registerRequest);

    console.log(`=== Response status: ${response.status} ===`);
    if (response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== User registered succesfully ===`);
    const responseJson = await response.json();
    console.log(JSON.stringify(responseJson, null, 2));
    return responseJson.config;
}

async function createActor(configEndpoint: string, id: string, description: string) {
    console.log(`=== Creating actor at ${configEndpoint} ===`);

    const actorRequest = {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id, description })
    };

    const response = await fetch(configEndpoint, actorRequest);
    console.log(`=== Response status: ${response.status} ===`);

    if (response.status !== 202 && response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== Actor accepted ===`);
    const actor = await response.json();
    console.log(JSON.stringify(actor, null, 2));

    console.log(`=== Waiting for actor to become ready ===`);

    // Listen to actor status SSE endpoint
    await waitForActorReady(actor.status);

    console.log(`✅ Actor ${actor.id} is ready and available:`);
    console.log(`configuration: ${actor.config}`);
    console.log(`endpoints: ${actor.endpoints}`);
}

async function waitForActorReady(statusUrl: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const evtSource = new EventSource(statusUrl);

        evtSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);

                if (data.type === "ready") {
                    console.log("✅ Actor is ready:", data.message || "");
                    evtSource.close();
                    resolve();
                } else if (data.type === "error") {
                    console.error("❌ Actor failed:", data.message || "");
                    evtSource.close();
                    reject(new Error(data.message || "Actor error"));
                } else {
                    console.log(`ℹ️  Event [${data.type}]: ${data.message || ""}`);
                }
            } catch (err) {
                console.error("Invalid SSE message:", event.data);
            }
        };

        evtSource.onerror = (err) => {
            console.error("SSE connection error:", err);
            evtSource.close();
            reject(new Error("SSE connection failed"));
        };
    });
}

async function main() {
    const configEndpoint = await register(ID, SECRET, ISSUER, NAME, AS_URL);
    await createActor(configEndpoint, ACTOR_ID, DESCRIPTION);
}

main().catch(console.error);
