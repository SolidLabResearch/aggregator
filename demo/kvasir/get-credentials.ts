import { KeycloakOIDCAuth } from "../util.js";

const IDP = "http://localhost:8280";
const REALM = "quarkus";
const USERNAME = "alice@example.com";
const PASSWORD = "alice";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "bF9L3p1uGQNofLnixJviG7BR9L17ce9F";

const UMA_SERVER = "http://localhost:4000/uma";
const KVASIR_SERVER = "http://localhost:8080/test";

async function main() {
  try {
    console.log("=== Initializing Keycloak Authentication ===");
    
    // const auth = new KeycloakOIDCAuth();
    // await auth.init(IDP, REALM);
    // await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

    // 1️⃣ Fetch UMA config
    const configRes = await fetch(
      `${UMA_SERVER}/.well-known/uma2-configuration`
    );

    if (!configRes.ok) {
      throw new Error(`Failed to fetch UMA config: ${configRes.status}`);
    }

    const config = await configRes.json();

    // 2️⃣ Get registration_endpoint
    const registrationEndpoint = config.registration_endpoint;
    if (!registrationEndpoint) {
      throw new Error("registration_endpoint not found in UMA config");
    }

    console.log("Registration endpoint:", registrationEndpoint);

    // 3️⃣ Send POST request to registration_endpoint
    const registrationRes = await fetch(registrationEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // "Authorization": `Bearer ${await auth.getIdToken()}`,
      },
      body: JSON.stringify({
        client_uri: KVASIR_SERVER,
      }),
    });

    if (!registrationRes.ok) {
      throw new Error(
        `Registration failed: ${registrationRes.status}`
      );
    }

    // 4️⃣ Print JSON response
    const registrationJson = await registrationRes.json();
    console.log("Registration response:");
    console.log(registrationJson);

  } catch (err) {
    console.error("Error:", (err as Error).message);
  }
}

main();
