import { KeycloakOIDCAuth } from "../util.js";
import { toGraphQLObject } from "./graphql.js";

export class KvasirManagement {

  private podUrl: string;
  private umaUrl: string;

  private auth: KeycloakOIDCAuth;
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

  public async registerPolicies(turtle: string, assigner: string) {
    const policyUri = `${this.umaUrl}/policies`;

    try {
      const resp = await fetch(policyUri, {
        method: "POST",
        headers: {
          "Content-Type": "text/turtle",
          "Authorization": assigner,
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
          "Authorization": assigner,
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

  public async deletePolicies(assigner: string, policyIds: string[]) {
    async function deletePolicy(policyId: string, umaUrl: string) {
      const policyUri = `${umaUrl}/policies/${encodeURIComponent(policyId)}`;
      try {
        const resp = await fetch(policyUri, {
          method: "DELETE",
          headers: {
            "Content-Type": "text/turtle",
            "Authorization": assigner,
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
      await deletePolicy(id, this.umaUrl);
    }
  }

  public async registerSlice(
    podName: string, 
    context: any, 
    schema: string, 
    sliceName: string,
    sliceDescription: string,
  ): Promise<string> {
    const sliceUri = `${this.podUrl}/${podName}/slices`;

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

  public async addData(slice: string, context: any, name: string, data: Record<string, string>) {
    const fields = toGraphQLObject(data);
    const body = {
      "@context": context,
      "query": `mutation {
        add(${name}: {
          ${fields}
        })
      }`
    };

    const resp = await this.umaFetch(`${slice}/query`, { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }, 
      body: JSON.stringify(body), 
    });

    if (!resp.ok) {
      throw new Error(`${resp.status} ${resp.statusText}: ${await resp.text()}`);
    }

    console.log(`Data added`);
  }
}