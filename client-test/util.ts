import {fetch} from 'cross-fetch';
import {createDpopHeader, generateDpopKeyPair, KeyPair} from "@inrupt/solid-client-authn-core";

/**
 * Solid OIDC authenticated fetcher with DPoP support
 */
export class SolidOIDCAuth {
    private dpopKey: KeyPair | undefined;
    private authString: string | undefined;
    private accessToken: string | undefined;
    private expiresAt: number | undefined;

    constructor(private webId: string, private cssBaseURL: string) {}

    async init(email: string, password: string) {
        // Generate DPoP key pair
        this.dpopKey = await generateDpopKeyPair();

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
        if (!this.authString || !this.dpopKey) {
            throw new Error('Not initialized');
        }

        const tokenURL = `${this.cssBaseURL}/.oidc/token`;

        const response = await fetch(tokenURL, {
            method: 'POST',
            headers: {
                authorization: `Basic ${Buffer.from(this.authString).toString('base64')}`,
                'content-type': 'application/x-www-form-urlencoded',
                dpop: await createDpopHeader(tokenURL, 'POST', this.dpopKey),
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

    private async createClaimToken(tokenEndpoint: string): Promise<string> {
        await this.ensureValidToken();

        if (!this.accessToken || !this.dpopKey) {
            throw new Error('Not initialized');
        }

        return JSON.stringify({
            'Authorization': 'DPoP ' + this.accessToken,
            'DPoP': await createDpopHeader(tokenEndpoint, 'POST', this.dpopKey)
        });
    }

    private parseAuthenticateHeader(headers: Headers): { tokenEndpoint: string; ticket: string } {
        const wwwAuthenticateHeader = headers.get("WWW-Authenticate")
        if (!wwwAuthenticateHeader) throw Error("No WWW-Authenticate Header present");

        const { as_uri, ticket } = Object.fromEntries(wwwAuthenticateHeader.replace(/^UMA /, '').split(', ').map(
          param => param.split('=').map(s => s.replace(/"/g, ''))
        ));

        const tokenEndpoint = as_uri + "/token" // NOTE: should normally be retrieved from .well-known/uma2-configuration

        return {
            tokenEndpoint,
            ticket
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

            // Get UMA ticket
            const {tokenEndpoint, ticket} = this.parseAuthenticateHeader(noTokenResponse.headers);

            // Create claim with Solid OIDC
            const claimToken = await this.createClaimToken(tokenEndpoint);

            const content = {
                grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
                ticket,
                claim_token: claimToken,
                claim_token_format: 'http://openid.net/specs/openid-connect-core-1_0.html#IDToken',
            };

            // Request RPT from authorization server
            const asRequestResponse = await fetch(tokenEndpoint, {
                method: "POST",
                headers: {
                    "content-type": "application/json"
                },
                body: JSON.stringify(content),
            });

            if (asRequestResponse.status !== 200) {
                return asRequestResponse;
            }

            const asResponse = await asRequestResponse.json();

            // Add RPT to request headers
            const headers = new Headers(init.headers);
            headers.set('Authorization', `${asResponse.token_type} ${asResponse.access_token}`);

            // Retry request with RPT
            return fetch(url, {...init, headers});
        }
    }
}
