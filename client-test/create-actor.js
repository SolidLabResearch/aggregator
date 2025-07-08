
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
    config:sources ( "https://maartyman.github.io/static-files/test.ttl"^^xsd:string ) ;
    config:queryString "SELECT * WHERE { ?s ?p ?o }" .
`;

async function main() {
    const fetch = require('node-fetch');
    const { URL } = require('url');

    const pipelineEndpoint = 'http://localhost:5000/config/actors';
    const pipelineUrl = new URL(pipelineEndpoint);

    console.log(`=== Requesting pipeline at ${pipelineUrl} with body:\n`);
    console.log(PipelineDescription);
    console.log('');

    const response = await fetch(pipelineUrl, {
        method: "POST",
        headers: {
            "content-type": "text/turtle"
        },
        body: PipelineDescription,
    });

    if (response.status !== 200) {
        console.error(`Error: ${response.status}, response: ${await response.text()}`);
        return;
    }

    console.log(`= Status: ${response.status}\n`);
}

main();
