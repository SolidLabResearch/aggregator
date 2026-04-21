type UMAConfig = {
  token_endpoint: string;
  issuer?: string;
};

type OpenIDConfig = {
  token_endpoint: string;
  authorization_endpoint?: string;
  issuer?: string;
};

type RPT = {
    token_type: string;
    access_token: string;
}


export async function getUMAConfig(as_uri: string): Promise<UMAConfig> {
    const config_uri = `${as_uri}/.well-known/uma2-configuration`;

    const response = await fetch(config_uri, {
        method: "GET",
        headers: { "Accept": "application/json" },
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch UMA config: ${response.status} ${response.statusText}`);
    }

    
    const config = await response.json();

    return config as UMAConfig;
}

async function parseAuthenticateHeader(wwwAuthenticateHeader: string): Promise<{ issuer: string, tokenEndpoint: string; ticket: string }> {
    const paramsPart = wwwAuthenticateHeader.replace(/^\w+\s+/, '');

    const params = Object.fromEntries(
    paramsPart.split(',').map(param => {
        const [key, value] = param.split('=');
        return [key.trim(), value.replace(/"/g, '').trim()];
    })
    );

    const { as_uri, ticket } = params;

    const config = await getUMAConfig(as_uri);
    // const serviceEndpoint = headers.get("Link")?.match(/<([^>]+)>;\s*rel="service-token-endpoint"/)?.[1];

    return {
        issuer: as_uri,
        tokenEndpoint: config.token_endpoint,
        ticket
    }
}

export class KeycloakOIDCAuth {
    private tokenEndpoint!: string;

    public accessToken: string | undefined;
    private idToken: string | undefined;
    private expiresAt: number | undefined;

    private username!: string;
    private password!: string;
    private clientId!: string;
    private clientSecret!: string;

    async init(idp: string) {
        const configEndpoint = `${idp}/.well-known/openid-configuration`

        const response = await fetch(configEndpoint, {
            method: "GET",
            headers: { "content-type": "application/json" },
        });

        if (!response.ok) {
            throw new Error(`Error fetching keycloak config: ${response.status} ${response.statusText} ${await response.text()}`);
        }

        const config = (await response.json()) as OpenIDConfig;

        this.tokenEndpoint = config.token_endpoint;
    }

    /**
     * Initialize Keycloak OIDC authentication
     */
    async login(username: string, password: string, client_id: string, client_secret: string) {
        this.username = username;
        this.password = password;
        this.clientId = client_id;
        this.clientSecret = client_secret;

        await this.refreshAccessToken();
    }

    private async directAccessTokenRequest(): Promise<any> {
        const params = new URLSearchParams({
            grant_type: 'password',
            username: this.username,
            password: this.password,
            client_id: this.clientId,
            client_secret: this.clientSecret,
            scope: "openid offline_access",
        });

        const response = await fetch(this.tokenEndpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params.toString(),
        });

        if (!response.ok) {
            throw new Error(`Keycloak login failed: ${response.status} ${await response.text()}`);
        }

        const data = await response.json();

        return data;
    }

    /**
     * Refresh access token
     */
    public async refreshAccessToken(): Promise<void> {
        const tokenResponse = await this.directAccessTokenRequest();
        this.accessToken = tokenResponse.access_token;
        this.idToken = tokenResponse.id_token;
        this.expiresAt = Date.now() + (tokenResponse.expires_in * 1000);
    }

    /**
     * Make sure access token is still valid, otherwise refresh it.
     */
    private async ensureValidTokens() {
        if (!this.accessToken || !this.expiresAt || Date.now() >= this.expiresAt - 500) {
            await this.refreshAccessToken();
        }
    }

    /**
     * Create the claim token used for UMA
     * (For Keycloak this is simply the OIDC access token)
     */
    public async getAccessToken(): Promise<string> {
        await this.ensureValidTokens();

        if (!this.accessToken || !this.idToken) throw new Error("Not initialized");

        return this.accessToken;
    }

    public async getIdToken() {
        await this.ensureValidTokens();

        if (!this.accessToken || !this.idToken) throw new Error("Not initialized");

        return this.idToken;
    }

    /**
     * Create the UMA fetch behavior
     */
    createUMAFetch() {
        return async (url: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
            // First attempt with no token
            const noTokenResponse = await fetch(url, {
                ...init,
            });

            if (noTokenResponse.status >= 200 && noTokenResponse.status < 300) {
                return noTokenResponse;
            }

            // Parse the UMA authenticate header
            const wwwAuthenticateHeader = noTokenResponse.headers.get("WWW-Authenticate");
            if (!wwwAuthenticateHeader) {
                return noTokenResponse;
            }
            const { issuer, tokenEndpoint, ticket } = await parseAuthenticateHeader(wwwAuthenticateHeader);

            // Create Keycloak OIDC access token as claim
            const claimToken = await this.getAccessToken();
            
            // UMA token exchange request
            const umaRequestBody = new URLSearchParams({
                grant_type: "urn:ietf:params:oauth:grant-type:uma-ticket",
                ticket,
                claim_token: claimToken,
                claim_token_format: "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
            });

            const umaResponse = await fetch(tokenEndpoint, {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: umaRequestBody.toString(),
            });

            if (!umaResponse.ok) {
                return umaResponse; // propagate error
            }

            const rptJson = (await umaResponse.json()) as RPT;

            // Add RPT to headers
            const newHeaders = new Headers(init.headers);
            newHeaders.set("Authorization", `${rptJson.token_type} ${rptJson.access_token}`);

            // Retry the original request
            return fetch(url, { ...init, headers: newHeaders });
        };
    }
}
