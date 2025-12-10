import { KeycloakOIDCAuth } from "../util.js";

const POD_PROVIDER = "https://pacsoi-kvasir.faqir.org";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";
const CLIENT_ID = "moveup-backend";
const CLIENT_SECRET = "GD7VyY29Eeim5BWfdTAFJ8FTDW7SeU2g";

const POD_NAME = "patient0";
const USER_ID = "d4c5e084-48ac-4c32-80e8-ec9276434bae";
const USERNAME = "patient0@example.com";
const PASSWORD = "patient0";

async function main() {
  try {
    const auth = new KeycloakOIDCAuth();
    await auth.init(IDP, REALM);
    await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

    const podUrl = `${POD_PROVIDER}/${POD_NAME}`
    const resp = await fetch(podUrl, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/ld+json",
        "Authorization": `Bearer ${await auth.createClaimToken("")}`
      },
    });

    if (!resp.ok) {
      const errorText = await resp.text();
      console.error(`Error ${resp.status}: ${errorText}`);
      return;
    }

    console.log("Response:", await resp.text());
  } catch (err) {
    console.error("Request failed:", err);
  }
}

main();