const PipelineDescription = `
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:execution a fno:Execution ;
    fno:executes config:echo ;
`;

const body = {
  name: "my-echo-pipeline",
  description: PipelineDescription,
  owner: {
    webid: "http://localhost:3000/alice/profile/card",
    email: "alice@example.com",
    password: "alice",
    as_url: "http://172.22.254.95:4000/uma"
  }
}

const request = {
    method: "POST",
    headers: {
        "content-type": "application/json"
    },
    body: JSON.stringify(body)
};

async function main() {
    const pipelineEndpoint = 'http://aggregator.local/config/pipelines';

    console.log(`=== Requesting pipeline at ${pipelineEndpoint}\n`);

    const response = await fetch(pipelineEndpoint, request);

    console.log(`=== Response status: ${response.status}`);
    if (response.status !== 201) {
        console.error(`Error: ${response.status}, response: ${await response.text()}`);
        return;
    }

    console.log(`=== Pipeline created successfully!`);
    const responseJson = await response.json();
    console.log(JSON.stringify(responseJson, null, 2));
}

main().catch(console.error);
