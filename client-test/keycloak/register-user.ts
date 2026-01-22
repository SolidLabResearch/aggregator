import { KeycloakOIDCAuth } from "../util.js";

const REGISTER_ENDPOINT = "http://aggregator.local/registration";

const USER_ID = "https://pacsoi-idp.faqir.org/users/056e2d71-21aa-4528-a9f8-735ad76f0baa";
const USERNAME = "doctor@example.com";
const PASSWORD = "7714";
const CLIENT_ID = "moveup-backend";
const CLIENT_SECRET = "GD7VyY29Eeim5BWfdTAFJ8FTDW7SeU2g";
const AS_URL = "http://wsl.local:4000/uma";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";

//const auth = new KeycloakOIDCAuth()
//await auth.init(IDP, REALM)
//await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

async function registerRequest(): Promise<string> {
    console.log(`=== Registering user at ${REGISTER_ENDPOINT} ===`);
    //await auth.refreshAccessToken();
    const registerRequest = {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            //"Authorization": `Bearer ${auth.accessToken}`
        },
        body: JSON.stringify({
            registration_type: "none",
        })
    };
    const response = await fetch(REGISTER_ENDPOINT, registerRequest);

    if (!response.ok) {
        return response.text();
    }
    return response.text()
}

async function main() {
    console.log(await registerRequest());
}

await main().catch(console.error);
