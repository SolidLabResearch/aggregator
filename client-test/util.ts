import {fetch} from 'cross-fetch';

export async function getUMAConfig(as_uri: string) {
    const config_uri = `${as_uri}/.well-known/uma2-configuration`;

    const response = await fetch(config_uri, {
        method: "GET",
        headers: { "Accept": "application/json" }
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch UMA config: ${response.status} ${response.statusText}`);
    }

    const config = await response.json();
    return config;
}

async function parseAuthenticateHeader(wwwAuthenticateHeader: string): Promise<{ issuer: string, tokenEndpoint: string; ticket: string }> {
    const { as_uri, ticket } = Object.fromEntries(wwwAuthenticateHeader.replace(/^UMA /, '').split(', ').map(
        param => param.split('=').map(s => s.replace(/"/g, ''))
    ));

    const config = await getUMAConfig(as_uri);
    // const serviceEndpoint = headers.get("Link")?.match(/<([^>]+)>;\s*rel="service-token-endpoint"/)?.[1];


    return {
        issuer: as_uri,
        tokenEndpoint: config.token_endpoint,
        ticket
    }
}

/**
 * Solid OIDC authenticated fetcher with DPoP support
 */
/**
 * Solid OIDC authenticated fetcher
 */
export class SolidOIDCAuth {
    private authString: string | undefined;
    private accessToken: string | undefined;
    private expiresAt: number | undefined;

    constructor(private webId: string, private cssBaseURL: string) {}

    async init(email: string, password: string) {
        // Step 1: Get controls from account endpoint
        let indexResponse = await fetch(`${this.cssBaseURL}/.account/`);
        let controls = (await indexResponse.json()).controls;

        // Step 2: Login with password
        let response = await fetch(controls.password.login, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        if (!response.ok) {
            throw new Error('Login failed: ' + await response.text());
        }
        const { authorization } = await response.json();

        // Step 3: Get controls with authorization
        indexResponse = await fetch(`${this.cssBaseURL}/.account/`, {
            headers: { authorization: `CSS-Account-Token ${authorization}` }
        });
        if (!indexResponse.ok) {
            throw new Error('Failed to get authenticated controls: ' + await indexResponse.text());
        }
        controls = (await indexResponse.json()).controls;

        // Step 4: Create client credentials
        response = await fetch(controls.account.clientCredentials, {
            method: 'POST',
            headers: {
                authorization: `CSS-Account-Token ${authorization}`,
                'content-type': 'application/json'
            },
            body: JSON.stringify({ name: 'client-test-token', webId: this.webId }),
        });

        const { id, secret } = await response.json();
        this.authString = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;

        // Get initial access token
        await this.refreshAccessToken();
    }

    private async refreshAccessToken() {
        if (!this.authString) {
            throw new Error('Not initialized');
        }

        const tokenURL = `${this.cssBaseURL}/.oidc/token`;

        const response = await fetch(tokenURL, {
            method: 'POST',
            headers: {
                authorization: `Basic ${Buffer.from(this.authString).toString('base64')}`,
                'content-type': 'application/x-www-form-urlencoded'
            },
            body: 'grant_type=client_credentials&scope=webid',
        });

        const accessTokenJson = await response.json();
        this.accessToken = accessTokenJson.access_token;
        this.expiresAt = Date.now() + (accessTokenJson.expires_in * 1000);
    }

    private async ensureValidToken() {
        if (!this.accessToken || !this.expiresAt || Date.now() >= this.expiresAt - 500) {
            await this.refreshAccessToken();
        }
    }

    private async createClaimToken(): Promise<string> {
        await this.ensureValidToken();

        if (!this.accessToken) {
            throw new Error('Not initialized');
        }

        return this.accessToken
    }

    private async parseAuthenticateHeader(headers: Headers): Promise<{ tokenEndpoint: string; ticket: string, serviceEndpoint: string | undefined }> {
        const wwwAuthenticateHeader = headers.get("WWW-Authenticate")
        if (!wwwAuthenticateHeader) throw Error("No WWW-Authenticate Header present");

        const { as_uri, ticket } = Object.fromEntries(wwwAuthenticateHeader.replace(/^UMA /, '').split(', ').map(
          param => param.split('=').map(s => s.replace(/"/g, ''))
        ));

        const config = await getUMAConfig(as_uri);
        const tokenEndpoint = config.token_endpoint;

        const serviceEndpoint = headers.get("Link")?.match(/<([^>]+)>;\s*rel="service-token-endpoint"/)?.[1];

        return {
            tokenEndpoint,
            ticket,
            serviceEndpoint
        }
    }

    /**
     * Create a UMA fetch function that uses Solid OIDC authentication
     */
    createUMAFetch() {
        return async (url: string, init: RequestInit = {}): Promise<Response> => {
            // Try request without token first
            const noTokenResponse = await fetch(url, init);
            if (noTokenResponse.status > 199 && noTokenResponse.status < 300) {
                console.log('No Authorization token was required.')
                return noTokenResponse;
            }

            const {tokenEndpoint, ticket} = await this.parseAuthenticateHeader(noTokenResponse.headers);

            const {token, tokenType, error} = await this.fetchAccessToken(tokenEndpoint, ticket);
            if (error) {
                throw error;
            }

            const headers = new Headers(init.headers);
            headers.set('Authorization', `${tokenType} ${token}`);

            // Retry request with RPT
            return fetch(url, {...init, headers});
        }
    }

    async fetchAccessToken(
      tokenEndpoint: string,
      request: string | { resource_id: string, resource_scopes: string[] }[],
      claims?: Record<string, any>[]
    ): Promise<{token?: string, tokenType?: string, error?: Error}> {
        let content: any;
        if (claims) {
            content = {
                grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
                claim_tokens: claims
            };
        } else {
            const claimToken = await this.createClaimToken();
            content = {
                grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
                claim_token: claimToken,
                claim_token_format: 'http://openid.net/specs/openid-connect-core-1_0.html#IDToken',
            };
            claims = [{
                claim_token: claimToken,
                claim_token_format: 'http://openid.net/specs/openid-connect-core-1_0.html#IDToken'
            }];
        }

        if (typeof request === 'string') {
            content.ticket = request;
        } else {
            content.permissions = request;
        }

        const asRequestResponse = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "content-type": "application/json"
            },
            body: JSON.stringify(content),
        });

        if (asRequestResponse.status === 403) {
            const asRequestResponseJson = await asRequestResponse.json();
            claims = await this.gatherClaims(claims, asRequestResponseJson.required_claims);
            return this.fetchAccessToken(tokenEndpoint, asRequestResponseJson.ticket, claims);
        }

        if (asRequestResponse.status !== 200) {
            return {error: new Error(`Failed to fetch access token, error: ${await asRequestResponse.text()}`), token: undefined, tokenType: undefined};
        }

        const asResponse = await asRequestResponse.json();
        return {token: asResponse.access_token, tokenType: asResponse.token_type, error: undefined};
    }

    async gatherClaims(claims: Record<string, any>[], requiredClaims: any[]): Promise<Record<string, any>[]> {
        for (const requiredClaim of requiredClaims) {
            switch (requiredClaim["claim_token_format"]) {
                case "http://openid.net/specs/openid-connect-core-1_0.html#IDToken":
                    claims.push({
                        claim_token: await this.createClaimToken(),
                        claim_token_format: 'http://openid.net/specs/openid-connect-core-1_0.html#IDToken'
                    });
                    break;
                case "urn:ietf:params:oauth:token-type:access_token":
                    const {token, error} = await this.fetchAccessToken(
                      requiredClaim.details.issuer + "/token",
                      [{
                          resource_id: requiredClaim.details.resource_id,
                          resource_scopes: requiredClaim.details.resource_scopes
                      }]
                    );
                    if (error) {
                        throw error;
                    }
                    claims.push({
                        claim_token: token,
                        claim_token_format: 'urn:ietf:params:oauth:token-type:access_token'
                    });
                    break;
                default:
                    throw new Error(`Unsupported claim token format: ${requiredClaim["claim_token_format"]}`);
            }
        }
        return claims;
    }

    async getUmaAuthorizationHeader(url: string, method: string = 'GET'): Promise<{token: string | undefined, serviceEndpoint: string | undefined}> {
        const initialResponse = await fetch(url, { method });
        const { tokenEndpoint, ticket, serviceEndpoint } = await this.parseAuthenticateHeader(initialResponse.headers);

        if (initialResponse.ok) {
            return {token: initialResponse.headers.get('authorization') ?? undefined, serviceEndpoint};
        }

        if (initialResponse.status !== 401) {
            throw new Error(`Unexpected response while obtaining UMA ticket: ${initialResponse.status} - ${await initialResponse.text()}`);
        }

        const { token } = await this.fetchAccessToken(ticket, tokenEndpoint);
        return {token, serviceEndpoint};
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

    async init(idpHost: string, realm: string) {
        const configEndpoint = `${idpHost}/realms/${realm}/.well-known/openid-configuration`

        const response = await fetch(configEndpoint, {
            method: "GET",
            headers: { "content-type": "application/json" }
        });

        if (!response.ok) {
            throw new Error(`Error fetching keycloak config: ${response.status} ${response.statusText} ${await response.text()}`);
        }

        const data = await response.json();

        this.tokenEndpoint = data.token_endpoint;
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
            scope: "openid",
        });

        const response = await fetch(this.tokenEndpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params.toString()
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
    private async ensureValidToken() {
        if (!this.accessToken || !this.expiresAt || Date.now() >= this.expiresAt - 500) {
            await this.refreshAccessToken();
        }
    }

    /**
     * Create the claim token used for UMA
     * (For Keycloak this is simply the OIDC access token)
     */
    public async createClaimToken(issuer: string): Promise<string> {
        await this.ensureValidToken();

        if (!this.accessToken || !this.idToken) throw new Error("Not initialized");

        return this.accessToken;
    }

    /**
     * Create the UMA fetch behavior
     */
    createUMAFetch() {
        return async (url: string, init: RequestInit = {}): Promise<Response> => {

            // First attempt with no token
            const noTokenResponse = await fetch(url, init);

            if (noTokenResponse.status >= 200 && noTokenResponse.status < 300) {
                console.log("No Authorization token was required.");
                return noTokenResponse;
            }

            // Parse the UMA authenticate header
            const wwwAuthenticateHeader = noTokenResponse.headers.get("WWW-Authenticate");
            if (!wwwAuthenticateHeader) {
                console.log("No WWW-Authenticate header was provided.");
                return noTokenResponse;
            }
            const { issuer, tokenEndpoint, ticket } = await parseAuthenticateHeader(wwwAuthenticateHeader);

            // Create Keycloak OIDC access token as claim
            const claimToken = await this.createClaimToken(issuer);
            

            // UMA token exchange request
            const umaRequestBody = {
                grant_type: "urn:ietf:params:oauth:grant-type:uma-ticket",
                ticket,
                claim_token: claimToken,
                claim_token_format: "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
            };

            const umaResponse = await fetch(tokenEndpoint, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(umaRequestBody)
            });

            if (!umaResponse.ok) {
                return umaResponse; // propagate error
            }

            const rptJson = await umaResponse.json();

            // Add RPT to headers
            const newHeaders = new Headers(init.headers);
            newHeaders.set("Authorization", `${rptJson.token_type} ${rptJson.access_token}`);

            // Retry the original request
            return fetch(url, { ...init, headers: newHeaders });
        };
    }
}
