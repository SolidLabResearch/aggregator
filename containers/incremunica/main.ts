import { QueryEngine } from '@comunica/query-sparql';
import { QueryEngine as QueryEngineInc } from '@incremunica/query-sparql-incremental';
import { isAddition } from '@incremunica/user-tools';
import { Store, Parser } from 'n3';
import http from "http";
import { URL } from "url";

const proxyUrl = process.env.http_proxy || process.env.HTTP_PROXY;
if (proxyUrl === undefined) {
  throw new Error('Environment variable PROXY_URL is not set. Please provide the URL of the proxy server.');
}

// Create custom fetch function that uses the proxy's /fetch endpoint
const customFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> = async (input: any, init?: any) => {
  // Prepare the request payload for the proxy
  const fetchRequest = {
    url: input.toString(),
    method: init?.method || 'GET',
    headers: init?.headers || {},
    body: init?.body ? init.body.toString() : ''
  };

  try {
    // Send request to proxy's /fetch endpoint and return the response directly
    const response = await fetch(`${proxyUrl}/fetch`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(fetchRequest)
    });

    // The proxy now returns the actual response, so we can return it directly
    return response;
  } catch (error) {
    console.error('Custom fetch error:', error);
    throw error;
  }
};

async function main() {
  const pipelineDescription = process.env.PIPELINE_DESCRIPTION;
  if (pipelineDescription === undefined) {
    throw new Error('Environment variable PIPELINE_DESCRIPTION is not set. Please provide a valid pipeline description.');
  }
  const pipelineParsingEngine = new QueryEngine();
  const pipelineDescriptionStore = new Store();
  const parser = new Parser();

  await new Promise<void>(
    (resolve, reject) => {
      parser.parse(pipelineDescription, (error, quad, _prefixes) => {
        if (error) {
          reject('Error parsing pipeline description: ' + error);
          return;
        }
        if (quad) {
          pipelineDescriptionStore.addQuad(quad);
        } else {
          // Parsing finished
          resolve();
        }
      });
    }
  );

  const queryInfoStream = await pipelineParsingEngine.queryBindings(`
PREFIX fno: <https://w3id.org/function/ontology#>
PREFIX config: <http://localhost:5000/config#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?queryString ?source WHERE {
    ?execution a fno:Execution .
    ?execution fno:executes config:SPARQLEvaluation .
    ?execution config:sources ?sourceElement .
    ?sourceElement (rdf:rest*/rdf:first) ?source .
    ?execution config:queryString ?queryString .
}
  `, {
    sources: [
      pipelineDescriptionStore
    ]
  })

  const queryInfo: {query: string, sources: [string, ...string[]]} = await new Promise(
    (resolve, reject) => {
      let queryString: string | undefined = undefined
      let sources: [string, ...string[]] | undefined = undefined;
      queryInfoStream.on('data', (data) => {
        if (queryString === undefined && data.get('queryString').value !== undefined) {
          queryString = data.get('queryString').value;
        }
        if (data.get('queryString').value === queryString) {
          if (sources === undefined) {
            sources = [data.get('source').value];
            return;
          }
          sources.push(data.get('source').value);
        }
      });
      queryInfoStream.on('end', () => {
        if (queryString === undefined) {
          reject(new Error('No query string found in the pipeline description.'));
          return
        }
        if (sources === undefined) {
          reject(new Error('No sources found in the pipeline description.'));
          return
        }
        resolve({ query: queryString, sources: sources });
      });
      queryInfoStream.on('error', (error) => {
        reject(error);
      });
    }
  );
  queryInfoStream.destroy();

  console.log(`Executing SPARQL SELECT query: ${queryInfo.query}`);
  console.log(`Using sources: ${JSON.stringify(queryInfo.sources)}`);

  const queryEngine = new QueryEngineInc();
  const bindingsStream = await queryEngine.queryBindings(queryInfo.query, {
    sources: queryInfo.sources,
    fetch: customFetch
  });

  const materializedView: Map<string,{bindings: any, count: number}> = new Map();
  bindingsStream.on('data', (bindings: any) => {
    const key = bindings.toString();
    if (isAddition(bindings)) {
      if (materializedView.has(key)) {
        materializedView.get(key)!.count++;
      } else {
        materializedView.set(key, { bindings: bindings, count: 1 });
      }
    } else {
      if (materializedView.has(key)) {
        const existingElement = materializedView.get(key)!;
        existingElement.count--;
        if (existingElement.count <= 0) {
          materializedView.delete(key);
        }
      } else {
        throw new Error('Received a removal for a binding that was not in the materialized view:' + key);
      }
    }
  });
  bindingsStream.on('end', () => {
    console.log('Query execution finished.');
  });
  bindingsStream.on('error', (error) => {
    // Log original error and wrap in a new Error with message
    console.error('Error during query execution:', error);
    // Do not throw here to avoid crashing the server; keep running
  });

  const server = http.createServer((req, res) => {
    console.log(`Received request: ${req.method} ${req.url}`);
    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "Content-Type": "application/sparql-results+json" });
      const variablesSet: Set<string> = new Set();
      const results: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }}[] = [];
      for (const materializedElement of materializedView.values()) {
        for (const variable of materializedElement.bindings.keys()) {
          variablesSet.add(variable.value);
        }
        let result: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }} = {};
        for (const [variable, value] of materializedElement.bindings) {
          if (value.termType === 'Literal') {
            result[variable.value] = {
              type: 'literal',
              value: value.value
            };
            if (value.datatype) {
              result[variable.value].datatype = value.datatype.value;
            }
            if (value.language) {
              result[variable.value]["xml:lang"] = value.language;
            }
          } else if (value.termType === 'NamedNode') {
            result[variable.value] = {
              type: 'uri',
              value: value.value
            };
          } else if (value.termType === 'BlankNode') {
            result[variable.value] = {
              type: 'bnode',
              value: value.value
            };
          }
        }
        for (let i = 0; i < materializedElement.count; i++) {
          results.push(result);
        }
      }

      const sparqlJson = {
        head: { vars: [...variablesSet.keys()] },
        results: { bindings: results },
      };

      res.end(JSON.stringify(sparqlJson, null, 2));
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
    }
  });

  server.listen(8080, () => {
    console.log("SPARQL SELECT result server running at http://localhost:8080/");
  });
}

main();
