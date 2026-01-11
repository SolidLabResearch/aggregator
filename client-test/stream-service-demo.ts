import { SolidOIDCAuth } from "./util.js";

// Pipeline description for querying Alice's name
const PipelineDescription = `
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "http://localhost:3000/alice/profile/card"^^xsd:string ) ;
    config:queryString "SELECT ?name WHERE { <http://localhost:3000/alice/profile/card#me> <http://xmlns.com/foaf/0.1/name> ?name }" .
`;

async function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function createService(umaFetch: any): Promise<string> {
    console.log('🚀 Creating service to query Alice\'s name...');

    const pipelineEndpoint = 'http://localhost:5000/config/services';
    const response = await umaFetch(pipelineEndpoint, {
        method: "POST",
        headers: {
            "content-type": "text/turtle"
        },
        body: PipelineDescription,
    });

    if (response.status !== 201) {
        throw new Error(`Failed to create service: ${response.status} - ${await response.text()}`);
    }

    const responseJson = await response.json();
    console.log('✅ Service created successfully!');
    console.log(`📄 Response: ${JSON.stringify(responseJson)}`);

    // Extract service ID from response
    const serviceId = responseJson.id;
    return serviceId;
}

async function getServiceUrl(serviceId: string): Promise<string> {
    return `http://localhost:5000/${serviceId}/events`;
}

async function connectToSSE(serviceUrl: string, umaFetch: any): Promise<void> {
    console.log(`🔗 Connecting to SSE stream at: ${serviceUrl}`);

    return new Promise((resolve, reject) => {
        let eventCount = 0;
        let hasSeenAddition = false;
        let hasSeenRemoval = false;
        let addAliceCallback: (() => Promise<void>) | null = null;
        let removeAliceCallback: (() => Promise<void>) | null = null;
        let streamCleanup: (() => void) | null = null;
        let isCompleted = false;

        // Create an AbortController to forcefully terminate the fetch
        const abortController = new AbortController();

        // Use fetch to connect to SSE endpoint
        umaFetch(serviceUrl, {
            method: "GET",
            headers: {
                "Accept": "text/event-stream",
                "Cache-Control": "no-cache"
            },
            signal: abortController.signal  // Add abort signal
        }).then((response: Response) => {
            if (!response.ok) {
                reject(new Error(`Failed to connect to SSE: ${response.status}`));
                return;
            }

            console.log('✅ Connected to SSE stream');

            if (!response.body) {
                reject(new Error('Response body is null or undefined'));
                return;
            }

            // Store the response object for complete cleanup
            let responseToCleanup = response;

            // Handle different types of response.body in Node.js
            let buffer = '';
            let currentEventType = '';

            const completeDemo = () => {
                if (isCompleted) return;
                isCompleted = true;

                console.log('🎉 Demo completed successfully - seen all expected events!');
                console.log('🧹 Cleaning up SSE connection...');

                // Abort the fetch request to close the connection
                try {
                    abortController.abort();
                } catch (abortError) {
                    // Abort errors are expected and can be ignored
                }

                // Clean up the stream
                if (streamCleanup) {
                    streamCleanup();
                }

                console.log('🏁 Demo completed - connection closed!');
                resolve();
            };

            const processEvent = (eventType: string, data: any) => {
                if (eventType === 'init') {
                    console.log('📊 Initial data received:');
                    // Simplify the results display
                    if (data.results && data.results.bindings) {
                        if (data.results.bindings.length === 0) {
                            console.log('   results: []');
                        } else {
                            const simplifiedResults = data.results.bindings.map((binding: any) => {
                                const result: any = {};
                                for (const [key, value] of Object.entries(binding)) {
                                    result[key] = (value as any).value;
                                }
                                return result;
                            });
                            console.log('   results:', JSON.stringify(simplifiedResults, null, 2));
                        }
                    }
                    eventCount++;

                    // Start the sequence by adding Alice's name
                    setTimeout(async () => {
                        if (addAliceCallback) {
                            console.log('🚀 Starting interactive sequence...');
                            try {
                                await addAliceCallback();
                            } catch (error) {
                                console.error('❌ Error adding Alice name:', error);
                                reject(error);
                            }
                        }
                    }, 1000);

                } else if (eventType === 'addition') {
                    console.log('➕ Addition event received:');
                    // Simplify the binding display
                    if (data.binding) {
                        const result: any = {};
                        for (const [key, value] of Object.entries(data.binding)) {
                            result[key] = (value as any).value;
                        }
                        console.log('   binding:', JSON.stringify(result, null, 2));
                    }
                    hasSeenAddition = true;
                    eventCount++;

                    // Automatically trigger removal after seeing addition
                    console.log('🔄 Addition detected, triggering removal...');
                    setTimeout(async () => {
                        if (removeAliceCallback) {
                            try {
                                await removeAliceCallback();
                            } catch (error) {
                                console.error('❌ Error removing Alice name:', error);
                                reject(error);
                            }
                        }
                    }, 1000);

                } else if (eventType === 'removal') {
                    console.log('➖ Removal event received:');
                    // Simplify the binding display
                    if (data.binding) {
                        const result: any = {};
                        for (const [key, value] of Object.entries(data.binding)) {
                            result[key] = (value as any).value;
                        }
                        console.log('   binding:', JSON.stringify(result, null, 2));
                    }
                    hasSeenRemoval = true;
                    eventCount++;

                    // End the demo after seeing removal
                    completeDemo();

                } else if (eventType === 'heartbeat') {
                    console.log('💓 Heartbeat received');
                }
            };

            // Check if it's a Web ReadableStream or Node.js stream
            if (typeof (response.body as any).getReader === 'function') {
                // Web ReadableStream approach
                console.log('Using Web ReadableStream approach');
                const reader = (response.body as ReadableStream).getReader();
                const decoder = new TextDecoder();

                streamCleanup = () => {
                    console.log('🔧 Canceling Web ReadableStream...');
                    reader.cancel().catch(console.error);
                };

                const processWebStream = async () => {
                    try {
                        while (!isCompleted) {
                            const { done, value } = await reader.read();

                            if (done) {
                                console.log('📡 SSE stream ended');
                                if (!isCompleted) {
                                    resolve();
                                }
                                return;
                            }

                            buffer += decoder.decode(value, { stream: true });
                            const lines = buffer.split('\n');
                            buffer = lines.pop() || '';

                            for (const line of lines) {
                                if (line.startsWith('event: ')) {
                                    currentEventType = line.substring(7);
                                    continue;
                                }

                                if (line.startsWith('data: ')) {
                                    const data = line.substring(6);
                                    try {
                                        const parsedData = JSON.parse(data);
                                        processEvent(currentEventType, parsedData);
                                    } catch (e) {
                                        // Ignore JSON parsing errors for heartbeat or other non-JSON data
                                    }
                                }
                            }
                        }
                    } catch (error) {
                        if (!isCompleted) {
                            console.error('❌ Error processing Web stream:', error);
                            reject(error);
                        }
                    }
                };

                processWebStream().catch((error) => {
                    if (!isCompleted) {
                        reject(error);
                    }
                });

            } else if (typeof (response.body as any).on === 'function') {
                // Node.js stream approach
                console.log('Using Node.js stream approach');
                const nodeStream = response.body as any;

                streamCleanup = () => {
                    console.log('🔧 Destroying Node.js stream...');
                    try {
                        if (nodeStream.destroy) {
                            nodeStream.destroy();
                        }
                        if (nodeStream.close) {
                            nodeStream.close();
                        }
                        // Also try to remove all listeners to ensure cleanup
                        if (nodeStream.removeAllListeners) {
                            nodeStream.removeAllListeners();
                        }
                        console.log('✅ Node.js stream cleanup completed');
                    } catch (error) {
                        console.error('❌ Error during stream cleanup:', error);
                    }
                };

                nodeStream.on('data', (chunk: Buffer) => {
                    if (isCompleted) return;

                    buffer += chunk.toString();
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';

                    for (const line of lines) {
                        if (line.startsWith('event: ')) {
                            currentEventType = line.substring(7);
                            continue;
                        }

                        if (line.startsWith('data: ')) {
                            const data = line.substring(6);
                            try {
                                const parsedData = JSON.parse(data);
                                processEvent(currentEventType, parsedData);
                            } catch (e) {
                                // Ignore JSON parsing errors for heartbeat or other non-JSON data
                            }
                        }
                    }
                });

                nodeStream.on('end', () => {
                    console.log('📡 SSE stream ended');
                    if (!isCompleted) {
                        resolve();
                    }
                });

                nodeStream.on('error', (error: Error) => {
                    if (!isCompleted) {
                        console.error('❌ SSE stream error:', error);
                        reject(error);
                    }
                });

            } else {
                // Fallback: try to use response.text() and parse manually
                console.log('Using fallback text() approach');
                response.text().then((text: string) => {
                    console.log('📊 Received complete response:', text);
                    resolve();
                }).catch(reject);
            }

            // Set up the callback functions
            addAliceCallback = async () => {
                console.log('📝 Adding Alice\'s name to her pod (using INSERT DATA - safe, additive)...');
                const response = await umaFetch('http://localhost:3000/alice/profile/card', {
                    method: "PATCH",
                    headers: {
                        "Content-Type": "application/sparql-update"
                    },
                    body: `
                        PREFIX foaf: <http://xmlns.com/foaf/0.1/>
                        INSERT DATA {
                            <http://localhost:3000/alice/profile/card#me> foaf:name "Alice Smith" .
                        }
                    `
                });

                if (!response.ok) {
                    throw new Error(`Failed to add name: ${response.status} - ${await response.text()}`);
                }

                console.log('✅ Alice\'s name added successfully (existing data preserved)');
            };

            removeAliceCallback = async () => {
                console.log('🗑️ Removing Alice\'s name from her pod (using DELETE DATA - safe, only removes specific triple)...');
                const response = await umaFetch('http://localhost:3000/alice/profile/card', {
                    method: "PATCH",
                    headers: {
                        "Content-Type": "application/sparql-update"
                    },
                    body: `
                        PREFIX foaf: <http://xmlns.com/foaf/0.1/>
                        DELETE DATA {
                            <http://localhost:3000/alice/profile/card#me> foaf:name "Alice Smith" .
                        }
                    `
                });

                if (!response.ok) {
                    throw new Error(`Failed to remove name: ${response.status} - ${await response.text()}`);
                }

                console.log('✅ Alice\'s name removed successfully (other data preserved)');
            };

        }).catch(reject);
    });
}

async function checkAliceProfile(umaFetch: any): Promise<void> {
    console.log('🔍 Checking current content in Alice\'s profile...');

    const response = await umaFetch('http://localhost:3000/alice/profile/card', {
        method: "GET",
        headers: {
            "Accept": "text/turtle"
        }
    });

    if (!response.ok) {
        throw new Error(`Failed to read profile: ${response.status} - ${await response.text()}`);
    }

    const content = await response.text();
    console.log('📄 Current profile content:');
    console.log(content);
    console.log(''); // Empty line for spacing
}


async function main() {
    console.log('🎬 Starting Interactive Server-Sent Events Demo');
    console.log('=============================================\n');

    console.log(`=== Initializing Solid OIDC authentication`);
    const auth = new SolidOIDCAuth(
      'http://localhost:3000/alice/profile/card#me',
      'http://localhost:3000'
    );
    await auth.init('alice@example.org', 'abc123');
    console.log(`=== Solid OIDC authentication initialized successfully\n`);

    const umaFetch = auth.createUMAFetch();

    try {
        // Step 1: Create the service
        const serviceId = await createService(umaFetch);
        await sleep(5000); // Give the service time to start

        // Step 2: Get the SSE URL
        const sseUrl = await getServiceUrl(serviceId);

        // Step 3: Check current profile content
        await checkAliceProfile(umaFetch);

        // Step 4: Connect to SSE and wait for the interactive sequence to complete
        console.log('🔗 Setting up interactive SSE connection...');
        await connectToSSE(sseUrl, umaFetch);

        // The connectToSSE promise will only resolve when the demo is complete
        console.log('\n🏁 Demo completed successfully!');

    } catch (error) {
        console.error('❌ Demo failed:', error);
        process.exit(1);
    }
}

main().catch((error) => {
    console.error('❌ Unhandled error:', error);
    process.exit(1);
});
