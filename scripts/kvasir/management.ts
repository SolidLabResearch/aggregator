import { KeycloakOIDCAuth } from "../util.js";

type KvasirValue =
  | string
  | number
  | boolean
  | null
  | { [key: string]: KvasirValue };

type KvasirInsert = Record<string, KvasirValue>;

export class KvasirManagement {

  private podUrl: string;
  private umaUrl: string;

  public auth: KeycloakOIDCAuth;
  private umaFetch: (url: string, init?: RequestInit) => Promise<Response> = async () => {
    throw new Error("UMA fetch called before login");
  };

  constructor(podUrl: string, umaUrl: string) {
    this.podUrl = podUrl;
    this.umaUrl = umaUrl;

    this.auth = new KeycloakOIDCAuth();
  }

  public async init(idp: string, realm: string) {
    await this.auth.init(idp, realm);
  }

  public async login(username: string, password: string, clientId: string, clientSecret: string) {
    await this.auth.login(username, password, clientId, clientSecret);
    this.umaFetch = this.auth.createUMAFetch();
  }

  public async delegatePodToUMA() {
    const relationsUri = this.podUrl + "/rebac/relationships";
    console.log("POD URL: ", this.podUrl)
    try {
      const resp = await fetch(relationsUri, {
        method: "POST",
        headers: {
          "Content-Type": "application/ld+json",
          "Authorization": `Bearer ${await this.auth.getAccessToken()}`
        },
        body: JSON.stringify({
          "@context": {
            "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
            "kss-fga": "https://kvasir.discover.ilabt.imec.be/fine-grained-access#"
          },
          "kss:insert": [
            {
              "@id": "urn:kvasir-wildcard",
              "@type": "kss-fga:User",
              "kss-fga:owner": {
                "@id": this.podUrl,
                "@type": "kss-fga:Resource",
                "kss-fga:external_access": {
                  "@id": "kss-fga:Uma"
                }
              }
            }
          ]
        })
      });

      if (!resp.ok) {
        console.error(`Error ${resp.status}:`, await resp.text());
        return;
      }
      
      console.log(`Response ${resp.status}:, ${await resp.text()}`);
    } catch(err) {
      console.error("Request failed:", err);
    }
  }

  public async registerPolicies(turtle: string) {
    const policyUri = `${this.umaUrl}/policies`;

    try {
      const resp = await fetch(policyUri, {
        method: "POST",
        headers: {
          "Content-Type": "text/turtle",
          "Authorization": `Bearer ${await this.auth.getIdToken()}`,
        },
        body: turtle,
      });

      if (!resp.ok) {
        console.error(`Error ${resp.status}:`, await resp.text());
        return;
      }

      console.log(`Response ${resp.status}:, ${await resp.text()}`);
    } catch (err) {
      console.error("Request failed:", err);
    }
  }

  public async readPolicies(assigner: string) {
    const policyUri = `${this.umaUrl}/policies`;

    try {
      const resp = await fetch(policyUri, {
        method: "GET",
        headers: {
          "Content-Type": "text/turtle",
          "Authorization": `Bearer ${await this.auth.getAccessToken()}`,
        },
      });

      if (!resp.ok) {
        console.error(`Error ${resp.status}:`, await resp.text());
        return;
      }

      console.log(`Response ${resp.status}:, ${await resp.text()}`);
    } catch (err) {
      console.error("Request failed:", err);
    }
  }

  public async deletePolicies(policyIds: string[]) {
    async function deletePolicy(idToken: string, policyId: string, umaUrl: string) {
      const policyUri = `${umaUrl}/policies/${encodeURIComponent(policyId)}`;
      try {
        const resp = await fetch(policyUri, {
          method: "DELETE",
          headers: {
            "Content-Type": "text/turtle",
            "Authorization": `Bearer ${idToken}`,
          },
        });

        if (!resp.ok) {
          console.error(`Error ${resp.status}:`, await resp.text());
          return;
        }

        console.log("Deleted:", policyId, await resp.text());
      } catch (err) {
        console.error("Request failed:", err);
      }
    }

    for (const id of policyIds) {
      await deletePolicy(await this.auth.getIdToken(), id, this.umaUrl);
    }
  }

  public async registerSlice(
    context: any, 
    schema: string, 
    sliceName: string,
    sliceDescription: string,
  ): Promise<string> {
    const sliceUri = `${this.podUrl}/slices`;

    const body = {
      "@context": context,
      "kss:name": sliceName,
      "kss:description": sliceDescription,
      "kss:schema": schema
    };

    const resp = await this.umaFetch(sliceUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/ld+json",
      },
      body: JSON.stringify(body)
    });

    if (!resp.ok) {
      if (resp.status === 409) {
        console.log("Slice already exists");
        return `${sliceUri}/${sliceName}`;
      }
      const errorText = await resp.text();
      throw new Error(`Error Regestering slice ${resp.status}: ${errorText}`);
    }

    console.log(`Slice registered ${resp.status}`);
    return `${sliceUri}/${sliceName}`;
  }

  public async deleteSlice(slice: string) {
    try {
      const resp = await this.umaFetch(slice, {
        method: "DELETE",
      });

      if (!resp.ok) {
        const errorText = await resp.text();
        console.error(`Error ${resp.status}: ${errorText}`);
        return;
      }

      console.log(`Slice deleted`);
    } catch (err) {
      console.error("Request failed:", err);
    }
  }

  public async addData(
    slice: string,
    context: any,
    data: KvasirInsert[]
  ) {
    const transformRecord = (record: KvasirInsert): any => {
      const transformObject = (obj: KvasirInsert): any => {
        const result: Record<string, any> = {};

        for (const [key, value] of Object.entries(obj)) {
          // handle id -> @id at top level
          if (key === "id") {
            result["@id"] = value;
            continue;
          }

          // preserve JSON-LD keywords
          if (key.startsWith("@")) {
            result[key] = value;
            continue;
          }

          // replace first "_" with ":"
          const newKey = key.replace("_", ":");

          if (value !== null && typeof value === "object" && !Array.isArray(value)) {
            result[newKey] = transformObject(value as KvasirInsert);
          } else {
            result[newKey] = value;
          }
        }

        return result;
      };

      const transformed = transformObject(record);

      return transformed;
    };

    const body = {
      "@context": context,
      "kss:insert": data.map(transformRecord),
    };

    console.log("Adding data: ", JSON.stringify(body, null, 2))

    const resp = await this.umaFetch(`${slice}/changes`, {
      method: "POST",
      headers: { "Content-Type": "application/ld+json" },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      throw new Error(`${resp.status} ${resp.statusText}: ${await resp.text()}`);
    }
  }
}