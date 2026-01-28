import { KeycloakOIDCAuth } from "../util.js";

const SERVICES_ENDPOINT = "http://aggregator.local/39412d8b-7982-45ff-9c00-298fc7c43010/services";

const USERNAME = "doctor@example.com";
const PASSWORD = "doctor";
const CLIENT_ID = "moveup-app";
const CLIENT_SECRET = "Yg8rGkQNQ4OqDh3AUR81EoSJtjPDXH4n";

const SERVICE_ID = "comunica";
const DESCRIPTION = `
@base <http://aggregator.local/39412d8b-7982-45ff-9c00-298fc7c43010/> .
@prefix trans: <http://aggregator.local/transformations#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

<get-example-service> a fno:Execution ;
    fno:executes trans:Get ;
    trans:url "http://www.example.com" .
`;

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";

//const auth = new KeycloakOIDCAuth()
//await auth.init(IDP, REALM)
//await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);
//const umaFetch = auth.createUMAFetch();

async function createService(id: string, description: string) {
    console.log(`=== Creating service at ${SERVICES_ENDPOINT} ===`);

    const serviceRequest = {
        method: "POST",
        headers: { "content-type": "text/turtle" },
        body: DESCRIPTION
    };

    //const response = await umaFetch(SERVICES_ENDPOINT, serviceRequest);
    const response = await fetch(SERVICES_ENDPOINT, serviceRequest);
    console.log(`=== Response status: ${response.status} ===`);

    if (response.status !== 202 && response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== Service accepted ===`);
    const service = await response.text();
    console.log(service);
}

async function main() {
    await createService(SERVICE_ID, DESCRIPTION);
    //await waitForServiceReady("http://aggregator.local/config/a6785d0b-c31c-48f4-bb93-6ba25f105bf0/services/comunica/status");
}

main().catch(console.error);
