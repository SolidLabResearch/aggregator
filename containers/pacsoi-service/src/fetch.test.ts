import assert from "node:assert/strict";
import test from "node:test";
import { Agent } from "undici";
import {
  cancelledResponse,
  classifyFailure,
  createUmaProxyFetch,
  DEFAULT_FETCH_POLICY,
  type FetchPolicy,
  FetchScopes,
  fetchPolicyFromEnv,
  HostGate,
  parseRetryAfter,
  retryDelay,
  sleep,
} from "./fetch.js";

const FAST: FetchPolicy = {
  baseDelayMs: 1,
  maxDelayMs: 5,
  slowRetryDelayMs: 1,
  maxConcurrentPerHost: 6,
  breakerThreshold: 1000,
  breakerCooldownMs: 1,
  sourceFailureTimeoutMs: 60000,
};

const POD = "https://kvasir.example/pod-1";
const SLICE_URL = `${POD}/slices/WeightSlice/query`;
const STREAM_INIT: RequestInit = {
  method: "POST",
  headers: { Accept: "text/event-stream" },
  body: "{}",
};

function quiet<T>(fn: () => Promise<T>): Promise<T> {
  const saved = [console.info, console.warn, console.debug];
  console.info = console.warn = console.debug = () => {};
  return fn().finally(() => ([console.info, console.warn, console.debug] = saved));
}

test("classifyFailure separates host trouble, auth denials, and client errors", () => {
  assert.equal(classifyFailure(undefined), "transient");
  for (const status of [408, 425, 429, 500, 502, 503, 504]) assert.equal(classifyFailure(status), "transient");
  for (const status of [401, 403]) assert.equal(classifyFailure(status), "auth");
  for (const status of [400, 404, 405, 422]) assert.equal(classifyFailure(status), "client");
});

test("parseRetryAfter reads seconds and HTTP dates", () => {
  const now = Date.parse("2026-10-15T12:00:00Z");
  assert.equal(parseRetryAfter("7", now), 7000);
  assert.equal(parseRetryAfter("Thu, 15 Oct 2026 12:00:30 GMT", now), 30000);
  assert.equal(parseRetryAfter("Thu, 15 Oct 2026 11:00:00 GMT", now), 0);
  assert.equal(parseRetryAfter("soon", now), undefined);
  assert.equal(parseRetryAfter(null, now), undefined);
});

test("retryDelay applies full jitter, slow client retries, and Retry-After", () => {
  const p = DEFAULT_FETCH_POLICY;
  const half = () => 0.5;
  assert.equal(retryDelay(0, "transient", p, undefined, half), 500);
  assert.equal(retryDelay(3, "transient", p, undefined, half), 4000);
  assert.equal(retryDelay(50, "transient", p, undefined, half), p.maxDelayMs / 2);
  assert.equal(retryDelay(0, "transient", p, undefined, () => 0), 0);
  assert.equal(retryDelay(0, "client", p, undefined, () => 0), p.slowRetryDelayMs);
  assert.equal(retryDelay(0, "transient", p, 20000, () => 0), 20000);
  assert.equal(retryDelay(0, "transient", p, 10 * p.maxDelayMs, () => 0), p.maxDelayMs);
});

test("fetchPolicyFromEnv overrides defaults and rejects invalid values", () => {
  assert.deepEqual(fetchPolicyFromEnv({}), DEFAULT_FETCH_POLICY);
  assert.equal(fetchPolicyFromEnv({ FETCH_MAX_CONCURRENT_PER_HOST: "2" }).maxConcurrentPerHost, 2);
  assert.throws(() => fetchPolicyFromEnv({ FETCH_BREAKER_THRESHOLD: "0" }), /FETCH_BREAKER_THRESHOLD/);
  assert.throws(() => fetchPolicyFromEnv({ FETCH_MAX_DELAY_MS: "abc" }), /FETCH_MAX_DELAY_MS/);
});

test("FetchScopes are reference counted, prefix safe, and retire on close", () => {
  const scopes = new FetchScopes();
  assert.equal(scopes.signalFor(SLICE_URL), undefined);

  scopes.open(POD);
  scopes.open(POD + "/");
  const signal = scopes.signalFor(SLICE_URL)!;
  assert.equal(signal.aborted, false);
  assert.equal(scopes.signalFor("https://kvasir.example/pod-10/slices/x/query"), undefined);

  scopes.close(POD);
  assert.equal(signal.aborted, false, "still referenced by the second patient");
  scopes.close(POD);
  assert.equal(signal.aborted, true);
  assert.equal(scopes.signalFor(SLICE_URL)?.aborted, true, "late requests for a removed pod are cancelled");

  scopes.open(POD);
  assert.equal(scopes.signalFor(SLICE_URL)?.aborted, false, "re-adding the pod gets a fresh scope");
});

test("cancelledResponse is accepted by incremunica as an empty result", async () => {
  const json = cancelledResponse(false, SLICE_URL);
  assert.equal(json.ok, true);
  assert.equal(json.url, SLICE_URL);
  assert.deepEqual(await json.json(), { data: [] });

  const stream = cancelledResponse(true, SLICE_URL);
  assert.ok(stream.body, "incremunica rejects a null body");
  const { done } = await stream.body!.getReader().read();
  assert.equal(done, true);
});

test("HostGate limits concurrent attempts per host", async () => {
  const gate = new HostGate("h", { ...FAST, maxConcurrentPerHost: 2 });
  const signal = new AbortController().signal;
  const first = await gate.enter(signal);
  await gate.enter(signal);
  let thirdEntered = false;
  const third = gate.enter(signal).then((permit) => {
    thirdEntered = true;
    return permit;
  });
  await sleep(5);
  assert.equal(thirdEntered, false);
  first.done("success");
  (await third).done("success");
  assert.equal(thirdEntered, true);
});

test("HostGate opens after repeated transient failures and admits a single probe", async () => {
  let now = 0;
  const gate = new HostGate("h", { ...FAST, breakerThreshold: 2, breakerCooldownMs: 1000 }, undefined, () => now, () => 0);
  const signal = new AbortController().signal;
  (await gate.enter(signal)).done("transient");
  (await gate.enter(signal)).done("transient");

  // During the cooldown nobody enters.
  let entered = 0;
  const a = gate.enter(signal).then((p) => (entered++, p));
  const b = gate.enter(signal).then((p) => (entered++, p));
  await sleep(5);
  assert.equal(entered, 0);

  // After the cooldown exactly one request probes the host.
  now = 2000;
  const probe = await Promise.race([a, b]);
  await sleep(5);
  assert.equal(entered, 1);

  // A failed probe re-opens the breaker; a success would release the others.
  probe.done("success");
  await Promise.all([a, b]);
  assert.equal(entered, 2);
});

test("HostGate ignores aborted attempts and releases waiters on abort", async () => {
  const gate = new HostGate("h", { ...FAST, maxConcurrentPerHost: 1, breakerThreshold: 1, breakerCooldownMs: 60000 });
  const held = await gate.enter(new AbortController().signal);
  const controller = new AbortController();
  const waiting = gate.enter(controller.signal);
  controller.abort(new Error("stop"));
  await assert.rejects(waiting, /stop/);
  held.done("aborted");
  // The aborted outcome did not open the breaker.
  (await gate.enter(new AbortController().signal)).done("success");
});

test("umaProxyFetch retries transient failures and buffers the body", async () => {
  const statuses = [503, 502, 200];
  const calls: Array<{ url: string; body: any; signal?: AbortSignal | null }> = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    calls.push({ url, body: JSON.parse(init.body as string), signal: init.signal });
    const status = statuses.shift()!;
    return new Response(status === 200 ? '{"data":{"ok":true}}' : "busy", { status });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, fetchImpl, egressUrl: () => "http://egress/", random: () => 0 });

  const response = await quiet(() => umaFetch(SLICE_URL, { method: "POST", body: "{}" }));
  assert.equal(calls.length, 3);
  assert.equal(calls[0].url, "http://egress/fetch");
  assert.equal(calls[0].body.url, SLICE_URL);
  assert.equal(calls[0].body.authMode, "auto");
  assert.ok(calls[0].signal, "the egress request carries an abort signal");
  assert.equal(response.url, SLICE_URL);
  assert.deepEqual(await response.json(), { data: { ok: true } });
});

test("umaProxyFetch lifts the idle timeouts for event streams only", async () => {
  const dispatchers: unknown[] = [];
  const fetchImpl = (async (_url: string, init: RequestInit & { dispatcher?: unknown }) => {
    dispatchers.push(init.dispatcher);
    return new Response('{"data":[]}', { status: 200 });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, fetchImpl, egressUrl: () => "http://egress/", random: () => 0 });

  await quiet(() => umaFetch(SLICE_URL, { method: "POST", body: "{}", headers: { Accept: "text/event-stream" } }));
  await quiet(() => umaFetch(SLICE_URL, { method: "POST", body: "{}" }));

  assert.ok(dispatchers[0] instanceof Agent, "event streams use the no-idle-timeout dispatcher");
  assert.equal(dispatchers[1], undefined, "other requests keep fetch's default timeouts");
});

test("umaProxyFetch retries a body that breaks mid-transfer", async () => {
  let call = 0;
  const fetchImpl = (async () => {
    if (call++ === 0) {
      const body = new ReadableStream({
        start(c) {
          c.enqueue(new TextEncoder().encode('{"da'));
          c.error(new Error("socket hang up"));
        },
      });
      return new Response(body, { status: 200 });
    }
    return new Response('{"data":[]}', { status: 200 });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, fetchImpl, egressUrl: () => undefined, random: () => 0 });
  const response = await quiet(() => umaFetch(SLICE_URL));
  assert.equal(call, 2);
  assert.deepEqual(await response.json(), { data: [] });
});

test("umaProxyFetch ends quietly when the pod scope closes during backoff", async () => {
  const scopes = new FetchScopes();
  scopes.open(POD);
  let calls = 0;
  const fetchImpl = (async () => (calls++, new Response("down", { status: 503 }))) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    policy: { ...FAST, baseDelayMs: 60000, maxDelayMs: 60000 },
    scopes,
    fetchImpl,
    egressUrl: () => undefined,
    random: () => 1,
  });

  const pending = quiet(() => umaFetch(SLICE_URL, { method: "POST", body: "{}" }));
  await sleep(10);
  const started = Date.now();
  scopes.close(POD);
  const response = await pending;
  assert.ok(Date.now() - started < 1000, "the 60 s backoff was interrupted");
  assert.equal(calls, 1);
  assert.equal(response.ok, true);
  assert.deepEqual(await response.json(), { data: [] });
});

test("umaProxyFetch does not contact a pod whose scope is already closed", async () => {
  const scopes = new FetchScopes();
  scopes.open(POD);
  scopes.close(POD);
  let calls = 0;
  const fetchImpl = (async () => (calls++, new Response("x"))) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, scopes, fetchImpl, egressUrl: () => undefined });
  const response = await quiet(() => umaFetch(SLICE_URL, STREAM_INIT));
  assert.equal(calls, 0);
  assert.equal((await response.body!.getReader().read()).done, true);
});

test("umaProxyFetch rejects when the caller aborts", async () => {
  const fetchImpl = (async () => new Response("down", { status: 503 })) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    policy: { ...FAST, baseDelayMs: 60000, maxDelayMs: 60000 },
    fetchImpl,
    egressUrl: () => undefined,
    random: () => 1,
  });
  const controller = new AbortController();
  const pending = quiet(() => umaFetch(SLICE_URL, { signal: controller.signal }));
  await sleep(10);
  controller.abort(new Error("caller gave up"));
  await assert.rejects(pending, /caller gave up/);
});

test("umaProxyFetch keeps at most maxConcurrentPerHost attempts in flight", async () => {
  let inFlight = 0;
  let peak = 0;
  const fetchImpl = (async () => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await sleep(10);
    inFlight--;
    return new Response('{"data":[]}');
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    policy: { ...FAST, maxConcurrentPerHost: 2 },
    fetchImpl,
    egressUrl: () => undefined,
  });
  await quiet(() => Promise.all(Array.from({ length: 6 }, () => umaFetch(SLICE_URL))));
  assert.equal(peak, 2);
});

test("an open event stream ends gracefully when its pod scope closes", async () => {
  const scopes = new FetchScopes();
  scopes.open(POD);
  const events: string[] = [];
  scopes.onEvent = (_key, event) => events.push(event);
  let upstreamCancelled = false;
  const fetchImpl = (async () => {
    const body = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode("event: next\ndata: {}\n\n"));
      },
      cancel() {
        upstreamCancelled = true;
      },
    });
    return new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, scopes, fetchImpl, egressUrl: () => undefined });

  const response = await quiet(() => umaFetch(SLICE_URL, STREAM_INIT));
  const reader = response.body!.getReader();
  assert.equal((await reader.read()).done, false);
  const next = reader.read();
  scopes.close(POD);
  assert.equal((await next).done, true, "the reader sees a normal end, not an error");
  assert.equal(upstreamCancelled, true, "the upstream connection is released");
  assert.deepEqual(events, ["success"], "our own cancellation is not reported as a failure");
});

test("an upstream stream error becomes a normal end", async () => {
  const fetchImpl = (async () => {
    const body = new ReadableStream({
      start(c) {
        c.error(new Error("connection reset"));
      },
    });
    return new Response(body, { status: 200 });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, fetchImpl, egressUrl: () => undefined });
  const response = await quiet(() => umaFetch(SLICE_URL, STREAM_INIT));
  const result = await quiet(() => response.body!.getReader().read());
  assert.equal(result.done, true);
});

test("FetchScopes report a failure once per scope generation", () => {
  const scopes = new FetchScopes();
  const events: Array<[string, string]> = [];
  scopes.onEvent = (key, event) => events.push([key, event]);
  scopes.report(SLICE_URL, "failed");
  assert.equal(events.length, 0, "unscoped URLs report nothing");

  scopes.open(SLICE_URL);
  scopes.report(SLICE_URL, "success");
  scopes.report(SLICE_URL, "unauthorized");
  scopes.report(SLICE_URL, "failed");
  scopes.report(SLICE_URL, "success");
  assert.deepEqual(events.map(([, event]) => event), ["success", "unauthorized", "success"]);
  assert.equal(events[0][0], SLICE_URL);

  scopes.close(SLICE_URL);
  scopes.open(SLICE_URL);
  scopes.report(SLICE_URL, "failed");
  assert.deepEqual(events[events.length - 1], [SLICE_URL, "failed"], "a re-added source reports again");
});

test("a scoped 401/403 is reported at once and not retried", async () => {
  const scopes = new FetchScopes();
  scopes.open(SLICE_URL);
  const events: Array<[string, string, string | undefined]> = [];
  // The poller closes the scope when it suspends the source.
  scopes.onEvent = (key, event, reason) => {
    events.push([key, event, reason]);
    if (event !== "success") scopes.close(key);
  };
  let calls = 0;
  const fetchImpl = (async () => (calls++, new Response('{"message":"Request denied"}', { status: 403 }))) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, scopes, fetchImpl, egressUrl: () => undefined });

  const response = await quiet(() => umaFetch(SLICE_URL, { method: "POST", body: "{}" }));
  assert.equal(calls, 1);
  assert.deepEqual(events, [[SLICE_URL, "unauthorized", "Request denied"]]);
  assert.deepEqual(await response.json(), { data: [] }, "the engine sees an empty result, not an error");
});

test("other scoped failures are retried until the source failure timeout", async () => {
  let clock = 0;
  const scopes = new FetchScopes();
  scopes.open(SLICE_URL);
  const events: string[] = [];
  scopes.onEvent = (key, event) => {
    events.push(event);
    if (event !== "success") scopes.close(key);
  };
  let calls = 0;
  const fetchImpl = (async () => {
    calls++;
    clock += 400;
    return new Response("busy", { status: 503 });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    policy: { ...FAST, sourceFailureTimeoutMs: 1000 },
    scopes,
    fetchImpl,
    egressUrl: () => undefined,
    random: () => 0,
    now: () => clock,
  });

  await quiet(() => umaFetch(SLICE_URL));
  // Failing since 400; the attempt at 1600 is the first one past 1000 ms.
  assert.equal(calls, 4);
  assert.deepEqual(events, ["failed"]);
});

test("a scoped success is reported", async () => {
  const scopes = new FetchScopes();
  scopes.open(SLICE_URL);
  const events: string[] = [];
  scopes.onEvent = (_key, event) => events.push(event);
  const fetchImpl = (async () => new Response('{"data":[]}')) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, scopes, fetchImpl, egressUrl: () => undefined });
  await quiet(() => umaFetch(SLICE_URL));
  assert.deepEqual(events, ["success"]);
});

test("unscoped requests keep retrying on 401/403", async () => {
  const statuses = [403, 200];
  const fetchImpl = (async () => {
    const status = statuses.shift()!;
    return new Response(status === 200 ? "[]" : "denied", { status });
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    policy: FAST,
    scopes: new FetchScopes(),
    fetchImpl,
    egressUrl: () => undefined,
    random: () => 0,
  });
  const response = await quiet(() => umaFetch("https://hcp.example/active_patients", undefined, "oauth"));
  assert.deepEqual(await response.json(), []);
  assert.equal(statuses.length, 0);
});

test("a subscription that ends by itself is reported as failed", async () => {
  const scopes = new FetchScopes();
  scopes.open(SLICE_URL);
  const events: Array<[string, string | undefined]> = [];
  scopes.onEvent = (_key, event, reason) => events.push([event, reason]);
  const fetchImpl = (async () =>
    new Response("event: next\ndata: {}\n\n", {
      status: 200,
      headers: { "Content-Type": "text/event-stream" },
    })) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({ policy: FAST, scopes, fetchImpl, egressUrl: () => undefined });

  const response = await quiet(() => umaFetch(SLICE_URL, STREAM_INIT));
  const reader = response.body!.getReader();
  while (!(await quiet(() => reader.read())).done) {
    // Drain until the upstream closes.
  }
  assert.deepEqual(events, [["success", undefined], ["failed", "subscription ended"]]);
});

test("time blocked by an open breaker counts toward the failure timeout", async () => {
  const scopes = new FetchScopes();
  scopes.open(SLICE_URL);
  const events: Array<[string, string | undefined]> = [];
  scopes.onEvent = (key, event, reason) => {
    events.push([event, reason]);
    if (event !== "success") scopes.close(key);
  };
  let calls = 0;
  const fetchImpl = (async () => (calls++, new Response("busy", { status: 503 }))) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    // One failure opens the breaker for a minute; the source gives up after 50 ms.
    policy: { ...FAST, breakerThreshold: 1, breakerCooldownMs: 60000, sourceFailureTimeoutMs: 50 },
    scopes,
    fetchImpl,
    egressUrl: () => undefined,
    random: () => 0,
  });

  const started = Date.now();
  const response = await quiet(() => umaFetch(SLICE_URL));
  assert.ok(Date.now() - started < 1000, "did not wait for the breaker cooldown");
  assert.equal(calls, 1);
  assert.deepEqual(events, [["failed", "busy"]]);
  assert.deepEqual(await response.json(), { data: [] });
});

test("an event stream waiting for headers does not block other requests", async () => {
  let releaseStream!: () => void;
  const streamHeld = new Promise<void>((resolve) => (releaseStream = resolve));
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    if (new Headers(init.headers).get("Accept") === "text/event-stream") {
      await streamHeld; // a quiet subscription whose headers never come
      return new Response("", { status: 200, headers: { "Content-Type": "text/event-stream" } });
    }
    return new Response('{"data":[]}');
  }) as unknown as typeof fetch;
  const umaFetch = createUmaProxyFetch({
    policy: { ...FAST, maxConcurrentPerHost: 1 },
    fetchImpl,
    egressUrl: () => undefined,
  });

  const streams = [quiet(() => umaFetch(SLICE_URL, STREAM_INIT)), quiet(() => umaFetch(SLICE_URL, STREAM_INIT))];
  const started = Date.now();
  const response = await quiet(() => umaFetch(SLICE_URL));
  assert.ok(Date.now() - started < 500, "the query did not wait for the streams");
  assert.deepEqual(await response.json(), { data: [] });
  releaseStream();
  await Promise.all(streams);
});
