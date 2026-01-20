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

const auth = new KeycloakOIDCAuth()
await auth.init(IDP, REALM)
await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

async function registerRequest(as_url: string): Promise<any> {
    console.log(`=== Registering user at ${REGISTER_ENDPOINT} ===`);
    await auth.refreshAccessToken();
    const registerRequest = {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${auth.accessToken}`
        },
        body: JSON.stringify({
            registration_type: "client_credentials",
            id:
            authorization_server: as_url,
            client_id: CLIENT_ID
        })
    };
    const response = await fetch(REGISTER_ENDPOINT, registerRequest);

    if (!response.ok) {
        return response.text();
    }
    const registerResponse = await response.json();
    const params = new URLSearchParams({
        response_type: "code",
        client_id: registerResponse.aggregator_client_id,
        redirect_uri: "http://127.0.0.1:5173/callback",
        scope: "openid email offline_access",
        code_challenge: registerResponse.code_challenge,
        code_challenge_method: registerResponse.code_challenge_method,
        state: registerResponse.state,
    });

    const authUrl = `${IDP}/realms/${REALM}/protocol/openid-connect/auth?${params.toString()}`;
    console.log("Go to this URL in your browser:", authUrl);
}

async function main() {
    //await initRegistration(AS_URL);
    await finalizeRegistration("http://127.0.0.1:5173/callback?state=jHn_Hc0i1tiMQ2a0cEx9zR_PgNBUWuG0R2uWe_SMiDE%3D&session_state=cebb14bd-e3ed-4dfd-84f5-2bddaa4a7f02&iss=https%3A%2F%2Fpacsoi-idp.faqir.org%2Frealms%2Fkvasir&code=4bcb6d5a-4b8a-4a23-9fec-ca50387c91e3.cebb14bd-e3ed-4dfd-84f5-2bddaa4a7f02.49e34afa-2d63-4cee-a068-461a802d85c1");
}

await main().catch(console.error);
