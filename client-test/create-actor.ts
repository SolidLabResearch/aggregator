import { SolidOIDCAuth } from "./util.js";

/*
const PipelineDescription = `
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes config:FileRelay ;
    config:sources ( "https://maartyman.github.io/static-files/test.ttl"^^xsd:string "https://maartyman.github.io/static-files/test2.ttl"^^xsd:string ) .
`
 */
const PipelineDescription = `
@prefix trans: <http://localhost:5000/config/transformations#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:execution a fno:Execution ;
    fno:executes trans:SPARQLEvaluation ;
    trans:sources ( "http://localhost:3000/alice/private/resource"^^xsd:string ) ;
    trans:queryString "SELECT * WHERE { ?s ?p ?o }" .
`;

const request = {
    method: "POST",
    headers: {
        "content-type": "text/turtle"
    },
    body: PipelineDescription,
};

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

    console.log(`=== Creating private resource at http://localhost:3000/alice/private/resource.txt`);
    const tokenResponse = await umaFetch("http://localhost:3000/alice/private/resource", {
        method: 'PUT',
        headers: {
            'content-type': 'text/turtle'
        },
        body: '<> a <http://www.w3.org/2002/07/owl#Thing> .',
    })
    console.log('Create private resource status =', tokenResponse.status)
    if (tokenResponse.status < 200 || tokenResponse.status >= 300) {
        throw new Error(`Failed to create upstream resource, status ${tokenResponse.status}`)
    }

    console.log(`=== Requesting pipeline at ${pipelineEndpoint} with body:\n`);
    console.log(PipelineDescription);
    console.log('');

    const response = await umaFetch(pipelineEndpoint, request);

    console.log(`=== Response status: ${response.status}`);
    if (response.status !== 201) {
        console.error(`Error: ${response.status}, response: ${await response.text()}`);
        return;
    }

    console.log(`=== Pipeline created successfully!`);
    const responseText = await response.text();
    console.log(`Response: ${responseText}`);
}

main().catch(console.error);
