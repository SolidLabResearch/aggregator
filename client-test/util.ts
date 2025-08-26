import {fetch} from 'cross-fetch';

/**
 * Decodes a JSON Web Token (JWT) by parsing its payload.
 *
 * @param {string} token - The JSON Web Token to be parsed.
 * @returns {Object} The decoded payload of the JWT as a JavaScript object.
 *
 */
export function parseJwt(token: string): any {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
}

/**
 * Parses the 'WWW-Authenticate' header from the given headers to extract UMA session details.
 *
 * @param {Headers} headers - The HTTP headers from which the 'WWW-Authenticate' header is to be extracted.
 * @returns {UMA_Session} The parsed UMA session details.
 * @throws Will throw an error if the 'WWW-Authenticate' header is not present.
 */
export function parseAuthenticateHeader(headers: Headers): { tokenEndpoint: string; ticket: string } {
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
 * Authenticated fetcher following the User Managed Access 2.0 Grant for Oauth 2.0 Authorization flow
 * using one claim.
 * (https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
 */
const grant_type = 'urn:ietf:params:oauth:grant-type:uma-ticket';
export function createUserManagedAccessFetch(claim: { token: string; token_format: string }) {
    return async (url: string, init: RequestInit = {}): Promise<Response> => {
        // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.1
        // 3.1 Client Requests Resource Without Providing an Access Token
        const noTokenResponse = await fetch(url, init);
        if (noTokenResponse.status > 199 && noTokenResponse.status < 300) {
            console.log('No Authorization token was required.')
            return noTokenResponse;
        }
        // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.2
        // 3.2 Resource Server Responds to Client's Tokenless Access Attempt

        const {tokenEndpoint, ticket} = parseAuthenticateHeader(noTokenResponse.headers)

        const content = {
            grant_type: grant_type,
            ticket,
            claim_token: encodeURIComponent(claim.token),
            claim_token_format: claim.token_format,
        }

        // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.3.1
        // 3.3.1 Client Request to Authorization Server for RPT
        const asRequestResponse = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "content-type": "application/json"
            },
            body: JSON.stringify(content),
        });

        if (asRequestResponse.status !== 200) {
            // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.3.6
            // 3.3.6 Authorization Server Response to Client on Authorization  Failure
            // TODO: log properly
            return asRequestResponse
        }

        // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.3.5
        // 3.3.5 Authorization Server Response to Client on Authorization Success
        const asResponse = await asRequestResponse.json();

        // RPT added to header
        const headers = new Headers(init.headers);
        headers.set('Authorization', `${asResponse.token_type} ${asResponse.access_token}`);

        // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.4
        // 3.4 Client Requests Resource and Provides an RPT
        // https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.3.5
        // 3.5 Resource Server Responds to Client's RPT-Accompanied Resource Request
        return fetch(url, {...init, headers});
    }
}
