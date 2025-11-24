import {SolidOIDCAuth} from '../util.js';

async function main() {
    const pipelineEndpoint = 'http://localhost:5000/config/actors';

    console.log(`=== Initializing Solid OIDC authentication`);
    const auth = new SolidOIDCAuth(
      'http://localhost:3000/alice/profile/card#me',
      'http://localhost:3000'
    );
    await auth.init('alice@example.org', 'abc123');
    console.log(`=== Solid OIDC authentication initialized successfully\n`);

    const umaFetch = auth.createUMAFetch();

    console.log(`=== Requesting actors at ${pipelineEndpoint}`);

    const response = await umaFetch(pipelineEndpoint, {
        method: "GET"
    });
    console.log(`=== Response status: ${response.status}`);

    if (response.status !== 200) {
        console.error(`Error: ${response.status}, response: ${await response.text()}`);
        return;
    }

    let body = await response.json();
    let id = body.actors[0];
    console.log(`= Status: ${response.status}, id: ${id}\n`);

    const actorConfigUrl = pipelineEndpoint + `/${id}`;

    console.log(`=== Requesting actor config at ${actorConfigUrl}`);
    const actorResponse = await umaFetch(actorConfigUrl, {
        method: "GET"
    });
    console.log(`=== Actor config response status: ${actorResponse.status}`);
    if (actorResponse.status !== 200) {
        console.error(`Error: ${actorResponse.status}, response: ${await actorResponse.text()}`);
        return;
    }

    const actorConfig = await actorResponse.json();
    console.log(`= Actor config id:\n${actorConfig.id}\n`);
    console.log(`= Actor config transformation:\n${actorConfig.transformation}\n`);

    const actorUrl = "http://localhost:5000" + `/${id}/`;
    console.log(`=== Requesting actor results at ${actorUrl}`);

    const actorResultsResponse = await umaFetch(actorUrl, {
        method: "GET"
    });

    console.log(`=== Actor results response status: ${actorResultsResponse.status}`);
    if (actorResultsResponse.status !== 200) {
        console.error(`Error: ${actorResultsResponse.status}, response: ${await actorResultsResponse.text()}`);
        return;
    }

    const actorResults = await actorResultsResponse.text();
    console.log(`= Actor results:\n${actorResults}`);
}

main().catch(console.error);
