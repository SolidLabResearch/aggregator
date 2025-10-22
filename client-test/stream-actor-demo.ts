import { SolidOIDCAuth } from "./util.js";
import { fetch } from 'cross-fetch';

// Pipeline description for querying Alice's name
const PipelineDescription = `
@prefix trans: <http://localhost:5000/config/transformations#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes trans:SPARQLEvaluation ;
    trans:sources ( "http://localhost:3000/alice/profile/card"^^xsd:string ) ;
    trans:queryString "SELECT ?name WHERE { <http://localhost:3000/alice/profile/card#me> <http://xmlns.com/foaf/0.1/name> ?name }" .
`;

async function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function createActor(umaFetch: any): Promise<string> {
    console.log('🚀 Creating actor to query Alice\'s name...');

    const pipelineEndpoint = 'http://localhost:5000/config/actors';
    const response = await umaFetch(pipelineEndpoint, {
        method: "POST",
        headers: {
            "content-type": "text/turtle"
        },
        body: PipelineDescription,
    });

    if (response.status !== 201) {
        throw new Error(`Failed to create actor: ${response.status} - ${await response.text()}`);
    }

    const responseJson = await response.json();
    console.log('✅ Actor created successfully!');
    console.log(`📄 Response: ${JSON.stringify(responseJson)}`);

    // Extract actor ID from response
    const actorId = responseJson.id;
    return actorId;
}

async function getActorUrl(actorId: string): Promise<string> {
    return `http://localhost:5000/${actorId}/events`;
}

// Acquire a stream token for the SSE resource using UMA auth
async function getStreamToken(auth: SolidOIDCAuth, resourceUrl: string): Promise<{ token: string; expiresAtMs: number, sessionId: string, serviceEndpoint: string }>{
    const { token, serviceEndpoint } = await auth.getUmaAuthorizationHeader(resourceUrl, 'GET');
    if (!token) throw new Error('Failed to obtain UMA Authorization header');
    if (!serviceEndpoint) throw new Error('UMA service endpoint is undefined');

    const res = await fetch(serviceEndpoint, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'authorization': token,
        },
        body: JSON.stringify({ resource_url: resourceUrl }),
    });

    if (!res.ok) {
        throw new Error(`Failed to get stream token: ${res.status} - ${await res.text()}`);
    }

    const body = await res.json();
    return { token: body.service_token as string, expiresAtMs: (body.session_expires_at as number) * 1000, sessionId: body.session_id as string, serviceEndpoint };
}

// Refresh a stream token for the SSE resource
async function refreshStreamToken(auth: SolidOIDCAuth, resourceUrl: string, sessionId: string): Promise<{ expiresAtMs: number }>{
    const { token, serviceEndpoint } = await auth.getUmaAuthorizationHeader(resourceUrl, 'GET');
    if (!token) throw new Error('Failed to obtain UMA Authorization header');
    if (!serviceEndpoint) throw new Error('UMA service endpoint is undefined');

    const res = await fetch(serviceEndpoint, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'authorization': token,
        },
        body: JSON.stringify({ resource_url: resourceUrl, session_id: sessionId}),
    });

    if (!res.ok) {
        throw new Error(`Failed to refresh stream token: ${res.status} - ${await res.text()}`);
    }

    const body = await res.json();
    return { expiresAtMs: (body.session_expires_at as number) * 1000 };
}

async function connectToSSE(actorUrl: string, umaFetch: any, auth: SolidOIDCAuth): Promise<void> {
    console.log(`🔗 Connecting to SSE stream at: ${actorUrl}`);

    let addAliceCallback: (() => Promise<void>) | null = null;
    let removeAliceCallback: (() => Promise<void>) | null = null;

    // Keep reconnecting on proactive refresh until demo completes
    return new Promise(async (resolve, reject) => {
        let isCompleted = false;

        const runStream = async (streamToken: string) => {
            const abortController = new AbortController();

            try {
                console.log('🌐 Establishing SSE connection with stream token...');
                const response = await fetch(actorUrl, {
                    method: 'GET',
                    headers: {
                        'Accept': 'text/event-stream',
                        'Cache-Control': 'no-cache',
                        'Authorization': `Bearer ${streamToken}`,
                    },
                    signal: abortController.signal,
                });

                if (!response.ok) {
                    throw new Error(`Failed to connect to SSE: ${response.status} - ${await response.text()}`);
                }

                console.log('✅ Connected to SSE stream');

                if (!response.body) {
                    throw new Error('Response body is null or undefined');
                }

                let buffer = '';
                let currentEventType = '';

                const completeDemo = () => {
                    if (isCompleted) return;
                    isCompleted = true;
                    try { abortController.abort(); } catch {}
                    console.log('🎉 Demo completed successfully - closing stream');
                    resolve();
                };

                let amountOfResults = 0;
                const processEvent = (eventType: string, data: any) => {
                    if (eventType === 'up-to-date') {
                        console.log('🔄 up-to-date received: ', amountOfResults);
                        if (amountOfResults === 0) {
                            setTimeout(async () => {
                                if (addAliceCallback) {
                                    console.log('🚀 Starting interactive sequence (adding alice\'s name)...');
                                    try { await addAliceCallback(); } catch (e) { console.error(e); reject(e); }
                                }
                            }, 1000);
                        } else {
                            setTimeout(async () => {
                                if (removeAliceCallback) {
                                    console.log('🚀 New result received, triggering removal...');
                                    try { await removeAliceCallback(); } catch (e) { console.error(e); reject(e); }
                                }
                            }, 1000);
                        }
                    } else if (eventType === 'addition') {
                        console.log('➕ Addition event received:');
                        if (data.results?.bindings) {
                            const result: any = {};
                            for (const [key, value] of Object.entries(data.bindings)) {
                                amountOfResults++;
                                result[key] = (value as any).value;
                            }
                            console.log('   bindings:', JSON.stringify(result, null, 2));
                        }
                    } else if (eventType === 'deletion') {
                        console.log('➖ Deletion event received:');
                        if (data.results?.bindings) {
                            const result: any = {};
                            for (const [key, value] of Object.entries(data.results.bindings)) {
                                amountOfResults--;
                                result[key] = (value as any).value;
                            }
                            console.log('   bindings:', JSON.stringify(result, null, 2));
                        }
                        completeDemo();
                    } else if (eventType === 'heartbeat') {
                        console.log('💓 Heartbeat received');
                    }
                };

                // Web ReadableStream
                if (typeof (response.body as any).getReader === 'function') {
                    const reader = (response.body as ReadableStream).getReader();
                    const decoder = new TextDecoder();
                    try {
                        while (!isCompleted) {
                            const { done, value } = await reader.read();
                            if (done) break;
                            buffer += decoder.decode(value, { stream: true });
                            const lines = buffer.split('\n');
                            buffer = lines.pop() || '';
                            for (const line of lines) {
                                if (line.startsWith('event: ')) { currentEventType = line.substring(7); continue; }
                                if (line.startsWith('data: ')) {
                                    const data = line.substring(6);
                                    try { processEvent(currentEventType, JSON.parse(data)); } catch {}
                                }
                            }
                        }
                    } finally {
                        try { reader.cancel(); } catch {}
                    }
                // Node.js stream
                } else if (typeof (response.body as any).on === 'function') {
                    const nodeStream = response.body as any;
                    await new Promise<void>((res, rej) => {
                        nodeStream.on('data', (chunk: Buffer) => {
                            if (isCompleted) return;
                            buffer += chunk.toString();
                            const lines = buffer.split('\n');
                            buffer = lines.pop() || '';
                            for (const line of lines) {
                                if (line.startsWith('event: ')) { currentEventType = line.substring(7); continue; }
                                if (line.startsWith('data: ')) {
                                    const data = line.substring(6);
                                    try { processEvent(currentEventType, JSON.parse(data)); } catch {}
                                }
                            }
                        });
                        nodeStream.on('end', () => res());
                        nodeStream.on('error', (e: Error) => rej(e));
                    });
                } else {
                    // Fallback
                    const text = await response.text();
                    console.log('📊 Received complete response:', text);
                }
            } catch (e: any) {
                // Only swallow aborts triggered by our own completion; otherwise reject so caller can see the error
                if (e && e.name === 'AbortError' && isCompleted) {
                    return;
                }
                if (!isCompleted) {
                    return reject(e);
                }
            }
        };

        // Set up the callback functions (use umaFetch so Solid auth applies)
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

        try {
            let { token, expiresAtMs, sessionId } = await getStreamToken(auth, actorUrl);
            runStream(token);
            while (!isCompleted) {
                const refreshAt = expiresAtMs - 1100;
                while (!isCompleted && Date.now() < refreshAt) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
                if (isCompleted) break;
                console.log('🔁 Refreshing SSE stream session');
                const start = process.hrtime();
                ({ expiresAtMs } = await refreshStreamToken(auth, actorUrl, sessionId));
                const end = process.hrtime(start);
                console.log(`🔁 Refreshed SSE stream session (success in ${end[0]}s ${Math.round(end[1] / 1e6)}ms)`);
            }
        } catch (e) {
            if (!isCompleted) return reject(e);
        }
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
        // Step 1: Create the actor
        const actorId = await createActor(umaFetch);
        await sleep(5000); // Give the actor time to start

        // Step 2: Get the SSE URL
        const sseUrl = await getActorUrl(actorId);

        // Step 3: Check current profile content
        await checkAliceProfile(umaFetch);

        // Step 4: Connect to SSE with stream token flow
        console.log('🔗 Setting up interactive SSE connection (with stream token management)...');
        await connectToSSE(sseUrl, umaFetch, auth);

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
