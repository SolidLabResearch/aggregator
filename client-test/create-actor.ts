import {createUserManagedAccessFetch} from "./util.js";

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
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "http://localhost:3000/alice/profile/card"^^xsd:string ) ;
    config:queryString "SELECT * WHERE { ?s ?p ?o }" .
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

    console.log(`=== Requesting pipeline at ${pipelineEndpoint} with body:\n`);
    console.log(PipelineDescription);
    console.log('');

    const umaFetch = createUserManagedAccessFetch({
        token: "http://localhost:3000/alice/profile/card#me",
        token_format: 'urn:solidlab:uma:claims:formats:webid',
    })

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
