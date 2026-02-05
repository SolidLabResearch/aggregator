import { KeycloakOIDCAuth } from "../util.js";

const POD_PROVIDER = "https://pacsoi-kvasir.faqir.org";

const IDP = "https://pacsoi-idp.faqir.org";
const REALM = "kvasir";
const CLIENT_ID = "moveup-backend";
const CLIENT_SECRET = "GD7VyY29Eeim5BWfdTAFJ8FTDW7SeU2g";

const POD_NAME = "97fc4346-f2d6-49a4-ac09-6117233c1e05";
const USER_ID = "080645fd-f3a7-47a3-a841-77b035f59842";
const USERNAME = "patient0@example.com";
const PASSWORD = "1234";

async function main() {
  const auth = new KeycloakOIDCAuth();
  await auth.init(IDP, REALM);
  await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

  //await createPod(auth);
  await getPodConfig(auth);
}

async function createPod(auth: KeycloakOIDCAuth) {
  try {
    const body = {
      "@context": {
        "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
      },
      "kss:name": POD_NAME,
      "kss:ownerUserId": USER_ID,
      "kss:configuration": {
        "defaultContext": { so: "http://schema.org/" },
        "autoIngestRDF": "true",
        "auth": {
          "uma": {
            "server-url": "https://pacsoi-uma.faqir.org/"
          }
        }
      }
    };

    const resp = await fetch(POD_PROVIDER, {
      method: "POST",
      headers: {
        "Content-Type": "application/ld+json",
        "Authorization": `Bearer ${await auth.getAccessToken()}`
      },
      body: JSON.stringify(body)
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

async function getPodConfig(auth: KeycloakOIDCAuth) {
  try {
    const umaFetch = auth.createUMAFetch();
    const podUrl = new URL(POD_NAME, POD_PROVIDER).toString();
    const resp = await umaFetch(podUrl, {
      method: "GET",
      headers: {
        "Content-Type": "application/ld+json",
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