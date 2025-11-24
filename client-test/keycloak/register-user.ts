import { createParser } from "eventsource-parser";
import { KeycloakOIDCAuth } from "../util.js";

const REGISTER_ENDPOINT = "http://aggregator.local/register";

const USERNAME = "doctor@example.com";
const PASSWORD = "doctor";
const CLIENT_ID = "moveup-app";
const CLIENT_SECRET = "Yg8rGkQNQ4OqDh3AUR81EoSJtjPDXH4n";
const ISSUER = "http://wsl.local:3000/doctor";
const NAME = "doctor";
const AS_URL = "http://wsl.local:4000/uma";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";

const auth = new KeycloakOIDCAuth()
await auth.init(IDP, REALM)
await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);
const umaFetch = auth.createUMAFetch();

async function register(id: string, secret: string, issuer: string, name: string, as_url: string): Promise<any> {
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
    const response = await umaFetch(REGISTER_ENDPOINT, registerRequest);

    console.log(`=== Response status: ${response.status} ===`);
    if (response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== User registered succesfully ===`);
    const responseJson = await response.json();
    console.log(JSON.stringify(responseJson, null, 2));
    return responseJson;
}

async function main() {
    await register(USERNAME, PASSWORD, ISSUER, NAME, AS_URL);
}

main().catch(console.error);
