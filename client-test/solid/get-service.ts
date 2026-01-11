import {SolidOIDCAuth} from '../util.js';

async function main() {
    const pipelineEndpoint = 'http://localhost:5000/config/services';

    console.log(`=== Initializing Solid OIDC authentication`);
    const auth = new SolidOIDCAuth(
      'http://localhost:3000/alice/profile/card#me',
      'http://localhost:3000'
    );
    await auth.init('alice@example.org', 'abc123');
    console.log(`=== Solid OIDC authentication initialized successfully\n`);

    const umaFetch = auth.createUMAFetch();

    console.log(`=== Requesting services at ${pipelineEndpoint}`);

    const response = await umaFetch(pipelineEndpoint, {
        method: "GET"
    });
    console.log(`=== Response status: ${response.status}`);

    if (response.status !== 200) {
        console.error(`Error: ${response.status}, response: ${await response.text()}`);
        return;
    }

    const body = await response.json();
    if (!Array.isArray(body) || body.length === 0) {
        console.error(`Error: unexpected services response: ${JSON.stringify(body)}`);
        return;
    }
    const id = body[0].id;
    console.log(`= Status: ${response.status}, id: ${id}\n`);

    const serviceConfigUrl = pipelineEndpoint + `/${id}`;

    console.log(`=== Requesting service config at ${serviceConfigUrl}`);
    const serviceResponse = await umaFetch(serviceConfigUrl, {
        method: "GET"
    });
    console.log(`=== Service config response status: ${serviceResponse.status}`);
    if (serviceResponse.status !== 200) {
        console.error(`Error: ${serviceResponse.status}, response: ${await serviceResponse.text()}`);
        return;
    }

    const serviceConfig = await serviceResponse.json();
    console.log(`= Service config id:\n${serviceConfig.id}\n`);
    console.log(`= Service config transformation:\n${serviceConfig.transformation}\n`);

    const serviceUrl = "http://localhost:5000" + `/${id}/`;
    console.log(`=== Requesting service results at ${serviceUrl}`);

    const serviceResultsResponse = await umaFetch(serviceUrl, {
        method: "GET"
    });

    console.log(`=== Service results response status: ${serviceResultsResponse.status}`);
    if (serviceResultsResponse.status !== 200) {
        console.error(`Error: ${serviceResultsResponse.status}, response: ${await serviceResultsResponse.text()}`);
        return;
    }

    const serviceResults = await serviceResultsResponse.text();
    console.log(`= Service results:\n${serviceResults}`);
}

main().catch(console.error);
