import { KeycloakOIDCAuth } from "../util.js";

const SERVICES_ENDPOINT = "http://aggregator.local/config/8eef3823-5cbf-447c-abd9-9c848de3b402/services";

const USERNAME = "doctor@example.com";
const PASSWORD = "doctor";
const CLIENT_ID = "moveup-app";
const CLIENT_SECRET = "Yg8rGkQNQ4OqDh3AUR81EoSJtjPDXH4n";

const SERVICE_ID = "comunica";
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

async function createService(id: string, description: string) {
    console.log(`=== Creating service at ${SERVICES_ENDPOINT} ===`);

    const serviceRequest = {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id, description })
    };

    const response = await umaFetch(SERVICES_ENDPOINT, serviceRequest);
    console.log(`=== Response status: ${response.status} ===`);

    if (response.status !== 202 && response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== Service accepted ===`);
    const service = await response.json();
    console.log(JSON.stringify(service, null, 2));

    console.log(`=== Waiting for service to become ready ===`);
    await waitForServiceReady(service.status);

    console.log(`🔧 Service ${service.id} endpoints:`);
    console.log(`configuration: ${service.config}`);
    console.log(`endpoints: ${service.endpoints}`);
}


async function waitForServiceReady(statusUrl: string, intervalMs = 3000, timeoutMs = 60000): Promise<void> {
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
                console.log("✅ Service is ready");
                return;
            } else {
                console.log("⏳ Service not ready yet...");
            }
        } catch (err) {
            console.error("❌ Error checking status:", err);
        }

        // Check timeout
        if (Date.now() - startTime > timeoutMs) {
            throw new Error("Timeout waiting for service to become ready");
        }

        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
}

async function main() {
    await createService(SERVICE_ID, DESCRIPTION);
    //await waitForServiceReady("http://aggregator.local/config/a6785d0b-c31c-48f4-bb93-6ba25f105bf0/services/comunica/status");
}

main().catch(console.error);
