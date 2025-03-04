let tokenEndpoint = "http://localhost:4000/uma/token";
let ticket = process.argv[2];
let claim_token  = "https://pod.playground.solidlab.be/user1/profile/card#me"

let privateResource = "http://localhost:5000/test"

function parseJwt(token) {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
}

async function main() {
    const content = {
        grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
        ticket,
        claim_token: encodeURIComponent(claim_token),
        claim_token_format: 'urn:solidlab:uma:claims:formats:webid',
    };

    console.log(`=== Requesting token at ${tokenEndpoint} with ticket body:\n`);
    console.log(content);
    console.log('');

    const asRequestResponse = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
            "content-type": "application/json"
        },
        body: JSON.stringify(content),
    })

    // For debugging:
    //console.log("Authorization Server response:", await asRequestResponse.text());
    //throw 'stop'
    if (asRequestResponse.status !== 200) {
        console.error(`Error: ${asRequestResponse.status}, response: ${await asRequestResponse.text()}`);
        return;
    }

    const asResponse = await asRequestResponse.json();

    const decodedToken = parseJwt(asResponse.access_token);

    console.log(`= Status: ${asRequestResponse.status}\n`);
    console.log(`= Body (decoded):\n`);
    console.log({...asResponse, access_token: asResponse.access_token.slice(0, 10).concat('...')});
    console.log('\n');

    for (const permission of decodedToken.permissions) {
       console.log(`Permissioned scopes for resource ${permission.resource_id}:`, permission.resource_scopes)
    }

    console.log(`=== Trying to create private resource <${privateResource}> WITH access token.\n`);

    console.log({'Authorization': `${asResponse.token_type} ${asResponse.access_token}`});

    //const tokenResponse = await fetch(privateResource, request);

    //console.log(`= Status: ${tokenResponse.status}\n`);
}

main();
