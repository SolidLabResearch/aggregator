/**
 * Fetch adapter shared by every incremental query engine.
 *
 * Why this is more than a retry loop: incremunica turns any rejected fetch,
 * non-2xx response, or broken response body into an `error` event on the
 * per-pod iterator. The weight, procedure, and questionnaire queries union all
 * pods into one stream, and that union stays subscribed to errors even after a
 * pod's iterator ended. One failing pod would therefore destroy the projection
 * for every patient. Pod requests must never fail from the engine's point of
 * view: they either succeed, keep retrying, or end quietly with an empty result.
 *
 * Load protection, in the order a request meets it:
 * 1. Per-source scopes: when a source is removed, its pending and future
 *    requests end quietly. Scoped requests also report their outcome, so the
 *    source poller can suspend a source that is unauthorized (immediately) or
 *    keeps failing (after `sourceFailureTimeoutMs`) until its next poll.
 * 2. Per-host circuit breaker: after repeated transient failures, a host gets a
 *    shared cooldown and is then probed by a single request.
 * 3. Per-host concurrency limit: bounds simultaneous attempts per server.
 * 4. Retry delays use full jitter and respect `Retry-After`, so failed requests
 *    do not retry in lockstep.
 */

import { Agent } from "undici";

/**
 * Event streams stay open, and quiet, for as long as nothing changes. Node's
 * fetch ends a request after 300 s without headers or body data, which cut
 * every subscription after five minutes, so streams use a dispatcher without
 * those idle timeouts. Connecting is still bounded by the default timeout.
 */
const streamDispatcher = new Agent({ headersTimeout: 0, bodyTimeout: 0 });

export interface FetchPolicy {
  /** First retry ceiling; doubles on every attempt. */
  baseDelayMs: number;
  /** Upper bound for the exponential retry ceiling. */
  maxDelayMs: number;
  /** Minimum delay for client errors (4xx other than 401/403/408/425/429). */
  slowRetryDelayMs: number;
  /**
   * Simultaneous non-stream attempts per target host. Event streams do not
   * take a slot: a quiet subscription can wait long for its headers and would
   * otherwise block every other request to the host.
   */
  maxConcurrentPerHost: number;
  /** Consecutive transient failures that open the host's breaker. */
  breakerThreshold: number;
  /** How long an open breaker blocks the host before one probe is allowed. */
  breakerCooldownMs: number;
  /** How long a scoped source may keep failing before it is reported as failed. */
  sourceFailureTimeoutMs: number;
}

export const DEFAULT_FETCH_POLICY: FetchPolicy = {
  baseDelayMs: 1000,
  maxDelayMs: 300000,
  slowRetryDelayMs: 60000,
  maxConcurrentPerHost: 6,
  breakerThreshold: 5,
  breakerCooldownMs: 30000,
  sourceFailureTimeoutMs: 120000,
};

const POLICY_ENV: Record<keyof FetchPolicy, string> = {
  baseDelayMs: "FETCH_BASE_DELAY_MS",
  maxDelayMs: "FETCH_MAX_DELAY_MS",
  slowRetryDelayMs: "FETCH_SLOW_RETRY_DELAY_MS",
  maxConcurrentPerHost: "FETCH_MAX_CONCURRENT_PER_HOST",
  breakerThreshold: "FETCH_BREAKER_THRESHOLD",
  breakerCooldownMs: "FETCH_BREAKER_COOLDOWN_MS",
  sourceFailureTimeoutMs: "FETCH_SOURCE_FAILURE_TIMEOUT_MS",
};

/** Reads optional overrides; invalid values fail fast at startup. */
export function fetchPolicyFromEnv(env: NodeJS.ProcessEnv = process.env): FetchPolicy {
  const policy = { ...DEFAULT_FETCH_POLICY };
  for (const key of Object.keys(POLICY_ENV) as (keyof FetchPolicy)[]) {
    const raw = env[POLICY_ENV[key]];
    if (raw === undefined || raw === "") continue;
    const value = Number(raw);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`Environment variable ${POLICY_ENV[key]} must be a positive integer`);
    }
    policy[key] = value;
  }
  return policy;
}

// ---------------------------------------------------------------------------
// Failure classification and delays
// ---------------------------------------------------------------------------

/**
 * transient: the host is struggling or unreachable; counts toward the breaker.
 * auth: the host answered but access is denied; policies may change later.
 * client: the host answered but rejected the request; retried slowly because
 *         failing would break the shared query (see module comment).
 */
export type FailureClass = "transient" | "auth" | "client";

export function classifyFailure(status?: number): FailureClass {
  if (status === undefined) return "transient";
  if (status === 408 || status === 425 || status === 429 || status >= 500) return "transient";
  if (status === 401 || status === 403) return "auth";
  return "client";
}

/** Parses `Retry-After` as delta-seconds or an HTTP date. */
export function parseRetryAfter(header: string | null, now = Date.now()): number | undefined {
  if (!header) return undefined;
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1000;
  const date = Date.parse(trimmed);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - now);
}

/**
 * Full jitter: a uniform delay in [0, ceiling], where the ceiling grows
 * exponentially. Client errors wait at least `slowRetryDelayMs` (plus up to
 * half of it as jitter). A server-provided `Retry-After` is a lower bound,
 * capped at `maxDelayMs`.
 */
export function retryDelay(
  attempt: number,
  failure: FailureClass,
  policy: FetchPolicy,
  retryAfterMs?: number,
  random: () => number = Math.random,
): number {
  const ceiling = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** Math.min(attempt, 30));
  let delay = Math.floor(random() * ceiling);
  if (failure === "client") {
    delay = Math.max(delay, policy.slowRetryDelayMs + Math.floor(random() * policy.slowRetryDelayMs / 2));
  }
  if (retryAfterMs !== undefined) {
    delay = Math.max(delay, Math.min(retryAfterMs, policy.maxDelayMs));
  }
  return delay;
}

/** Resolves after `ms`, or rejects with the signal's reason once it aborts. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function untilAborted(promise: Promise<void>, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Per-source cancellation scopes
// ---------------------------------------------------------------------------

/** Outcome a scoped request reports to the source poller. */
export type SourceEvent = "success" | "unauthorized" | "failed";

interface Scope {
  controller: AbortController;
  refs: number;
  /** Whether a failure was reported in this generation of the scope. */
  failed: boolean;
}

/**
 * Cancellation scopes keyed by source URL (or any URL prefix ending at a path
 * segment). incremunica never aborts its own requests, so the source poller
 * opens a scope when it adds a source and closes it when it removes one.
 * Scopes are reference counted because patients sharing a pod share URLs.
 *
 * A closed key stays "retired" until it is opened again. Requests that the
 * engine starts later for an already removed source (for example the event
 * subscription that follows an initial query) are cancelled immediately
 * instead of retrying against a source nobody needs.
 *
 * Requests under an active scope report their outcome through `onEvent`.
 * A failure is reported at most once per scope generation.
 */
export class FetchScopes {
  onEvent?: (key: string, event: SourceEvent, reason?: string) => void;
  private readonly active = new Map<string, Scope>();
  private readonly retired = new Set<string>();

  open(prefix: string): void {
    const key = FetchScopes.key(prefix);
    this.retired.delete(key);
    const scope = this.active.get(key);
    if (scope) {
      scope.refs++;
    } else {
      this.active.set(key, { controller: new AbortController(), refs: 1, failed: false });
    }
  }

  close(prefix: string): void {
    const key = FetchScopes.key(prefix);
    const scope = this.active.get(key);
    if (!scope) return;
    if (--scope.refs > 0) return;
    this.active.delete(key);
    this.retired.add(key);
    scope.controller.abort(new Error(`Fetch scope closed: ${key}`));
  }

  /** The signal of the most specific scope covering `url`, if any. */
  signalFor(url: string): AbortSignal | undefined {
    const activeKey = this.match(url, this.active.keys());
    const retiredKey = this.match(url, this.retired);
    if (retiredKey && (!activeKey || retiredKey.length > activeKey.length)) {
      return AbortSignal.abort(new Error(`Fetch scope closed: ${retiredKey}`));
    }
    return activeKey ? this.active.get(activeKey)!.controller.signal : undefined;
  }

  /** Reports a request outcome for the active scope covering `url`. */
  report(url: string, event: SourceEvent, reason?: string): void {
    const key = this.match(url, this.active.keys());
    if (!key) return;
    const scope = this.active.get(key)!;
    if (event !== "success") {
      if (scope.failed) return;
      scope.failed = true;
    }
    this.onEvent?.(key, event, reason);
  }

  private match(url: string, keys: Iterable<string>): string | undefined {
    let best: string | undefined;
    for (const key of keys) {
      if ((url === key || url.startsWith(key + "/")) && (!best || key.length > best.length)) {
        best = key;
      }
    }
    return best;
  }

  private static key(prefix: string): string {
    return prefix.replace(/\/+$/, "");
  }
}

// ---------------------------------------------------------------------------
// Per-host gate: concurrency limit + circuit breaker
// ---------------------------------------------------------------------------

/** `aborted` releases the slot without changing the breaker state. */
export type AttemptOutcome = "success" | "aborted" | FailureClass;

export interface HostPermit {
  /** Releases the slot and records the outcome. Safe to call more than once. */
  done(outcome: AttemptOutcome, retryAfterMs?: number): void;
}

export class HostGate {
  private active = 0;
  private readonly waiters: Array<() => void> = [];
  private failures = 0;
  private openUntil = 0;
  private probe?: { promise: Promise<void>; resolve: () => void };

  constructor(
    private readonly host: string,
    private readonly policy: FetchPolicy,
    private readonly log: (event: string, fields: Record<string, unknown>) => void = () => {},
    private readonly now: () => number = Date.now,
    private readonly random: () => number = Math.random,
  ) {}

  /**
   * Waits until the breaker allows an attempt and a slot is free.
   * `onBreakerWait` is called whenever the request is held back by the breaker.
   */
  async enter(
    signal: AbortSignal,
    onBreakerWait?: () => void,
    useSlot = true,
  ): Promise<HostPermit> {
    let isProbe = false;
    for (;;) {
      if (signal.aborted) throw signal.reason;
      const wait = this.openUntil - this.now();
      if (wait > 0) {
        onBreakerWait?.();
        // Spread the wake-ups so waiters do not all hit the probe check at once.
        await sleep(wait + Math.floor(this.random() * Math.min(wait, 1000)), signal);
        continue;
      }
      if (this.failures >= this.policy.breakerThreshold) {
        if (this.probe) {
          onBreakerWait?.();
          await untilAborted(this.probe.promise, signal);
          continue;
        }
        let resolve!: () => void;
        const promise = new Promise<void>((r) => (resolve = r));
        this.probe = { promise, resolve };
        isProbe = true;
      }
      break;
    }

    try {
      if (useSlot) await this.acquireSlot(signal);
    } catch (error) {
      if (isProbe) this.finishProbe();
      throw error;
    }

    let released = false;
    return {
      done: (outcome, retryAfterMs) => {
        if (released) return;
        released = true;
        this.record(outcome, retryAfterMs);
        if (useSlot) this.releaseSlot();
        if (isProbe) this.finishProbe();
      },
    };
  }

  private record(outcome: AttemptOutcome, retryAfterMs?: number): void {
    if (outcome === "aborted") return;
    if (outcome !== "transient") {
      // Any answer that is not a transient failure proves the host is responsive.
      if (this.failures >= this.policy.breakerThreshold) {
        this.log("breaker-closed", { host: this.host });
      }
      this.failures = 0;
      this.openUntil = 0;
      return;
    }
    this.failures++;
    if (this.failures >= this.policy.breakerThreshold) {
      const cooldown = Math.max(
        this.policy.breakerCooldownMs,
        Math.min(retryAfterMs ?? 0, this.policy.maxDelayMs),
      );
      this.openUntil = this.now() + cooldown;
      this.log("breaker-open", {
        host: this.host,
        consecutive_failures: this.failures,
        cooldown_ms: cooldown,
      });
    }
  }

  private finishProbe(): void {
    const probe = this.probe;
    this.probe = undefined;
    probe?.resolve();
  }

  private acquireSlot(signal: AbortSignal): Promise<void> {
    if (this.active < this.policy.maxConcurrentPerHost) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      const grant = () => {
        signal.removeEventListener("abort", onAbort);
        this.active++;
        resolve();
      };
      const onAbort = () => {
        const index = this.waiters.indexOf(grant);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(signal.reason);
      };
      this.waiters.push(grant);
      signal.addEventListener("abort", onAbort, { once: true });
    });
  }

  private releaseSlot(): void {
    this.active--;
    this.waiters.shift()?.();
  }
}

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

export interface FetchTargetDescription {
  target: string;
  pod?: string;
  slice?: string;
}

/** Extracts stable, useful labels without logging URL query parameters. */
export function describeFetchTarget(target: string): FetchTargetDescription {
  try {
    const url = new URL(target);
    const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const slicesIndex = parts.indexOf("slices");
    return {
      target: url.origin + url.pathname,
      pod: slicesIndex > 0 ? parts[slicesIndex - 1] : undefined,
      slice: slicesIndex >= 0 ? parts[slicesIndex + 1] : undefined,
    };
  } catch {
    return { target };
  }
}

/** Logs unchanged failures on attempts 1, 2, 4, 8, ... instead of every retry. */
export function shouldLogFetchFailure(attempt: number, changed: boolean): boolean {
  return changed || attempt === 1 || (attempt & (attempt - 1)) === 0;
}

class FetchResponseError extends Error {
  constructor(
    public readonly status: number,
    public readonly reason: string,
    public readonly retryAfterMs?: number,
  ) {
    super(`Response not ok: ${status}${reason ? ` ${reason}` : ""}`);
  }
}

function fetchLog(
  level: "debug" | "info" | "warn",
  requestID: string,
  event: string,
  fields: Record<string, unknown> = {},
): void {
  if (level === "debug" && (process.env.LOG_LEVEL ?? "info").toLowerCase() !== "debug") return;
  const details = Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== "")
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(" ");
  const line = `[FETCH ${requestID}] ${event}${details ? ` ${details}` : ""}`;
  if (level === "warn") console.warn(line);
  else if (level === "debug") console.debug(line);
  else console.info(line);
}

function fetchFailureReason(body: string, statusText: string): string {
  const trimmed = body.trim();
  if (trimmed) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      const reason = parsed.message ?? parsed.description ?? parsed.error;
      if (typeof reason === "string" && reason.trim()) return reason.trim();
    } catch {
      // Keep the compact plain-text response below.
    }
    return trimmed.replace(/\s+/g, " ").slice(0, 200);
  }
  return statusText;
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

function withURL(response: Response, url: string): Response {
  Object.defineProperty(response, "url", {
    value: url,
    writable: false,
    enumerable: true,
    configurable: true,
  });
  return response;
}

/**
 * The response a cancelled pod request resolves with. incremunica closes the
 * source cleanly on an empty event stream, and maps `{"data":[]}` to zero
 * bindings. (`{"data":{}}` is not safe: it yields one empty resource that the
 * response mapper's filters dereference.)
 */
export function cancelledResponse(isStream: boolean, url: string): Response {
  const response = isStream
    ? new Response("", { status: 200, headers: { "Content-Type": "text/event-stream" } })
    : new Response('{"data":[]}', { status: 200, headers: { "Content-Type": "application/json" } });
  return withURL(response, url);
}

/**
 * Wraps a streaming body so it always ends without an error: on scope
 * cancellation it ends immediately and releases the upstream connection, and
 * an upstream read error ends the stream instead of erroring the shared query.
 * Any end that we did not cause is passed to `onUnexpectedEnd`, because a
 * subscription never resumes on its own.
 */
function guardStream(
  response: Response,
  signal: AbortSignal,
  url: string,
  onUnexpectedEnd: (reason: string) => void,
): Response {
  if (!response.body) return withURL(response, url);
  const reader = response.body.getReader();
  let finished = false;
  let onAbort: () => void = () => {};
  const finish = (controller: ReadableStreamDefaultController<Uint8Array>) => {
    if (finished) return;
    finished = true;
    signal.removeEventListener("abort", onAbort);
    try {
      controller.close();
    } catch {
      // Already closed.
    }
  };

  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      onAbort = () => {
        reader.cancel(signal.reason).catch(() => {});
        finish(controller);
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    },
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (finished) return;
        if (done) {
          if (!signal.aborted) onUnexpectedEnd("subscription ended");
          finish(controller);
        } else {
          controller.enqueue(value);
        }
      } catch (error) {
        if (!finished && !signal.aborted) onUnexpectedEnd((error as Error).message);
        finish(controller);
      }
    },
    cancel(reason) {
      finished = true;
      signal.removeEventListener("abort", onAbort);
      return reader.cancel(reason);
    },
  });

  return withURL(
    new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    }),
    url,
  );
}

// ---------------------------------------------------------------------------
// The fetch adapter
// ---------------------------------------------------------------------------

export type AuthMode = "auto" | "oauth";

export type UmaProxyFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
  authMode?: AuthMode,
) => Promise<Response>;

export interface UmaProxyFetchOptions {
  policy?: FetchPolicy;
  scopes?: FetchScopes;
  fetchImpl?: typeof fetch;
  egressUrl?: () => string | undefined;
  random?: () => number;
  now?: () => number;
}

function hostKey(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

function headerRecord(headers: HeadersInit | undefined): Record<string, string> {
  const record: Record<string, string> = {};
  if (!headers) return record;
  if (headers instanceof Headers) {
    headers.forEach((value, key) => (record[key] = value));
  } else if (Array.isArray(headers)) {
    headers.forEach(([key, value]) => (record[key] = value));
  } else {
    Object.assign(record, headers);
  }
  return record;
}

/**
 * Creates the fetch adapter. A stable request ID covers all retry attempts and
 * is forwarded to egress-UMA for cross-service correlation.
 *
 * Termination rules:
 * - Success: the response is returned. Non-stream bodies are buffered first, so
 *   a connection that breaks mid-body is retried like any other failure.
 * - Caller abort (`init.signal`): rejects with the abort reason, as fetch does.
 * - Scope cancellation (source removed): resolves with `cancelledResponse`.
 * - Scoped request, 401/403: reported as `unauthorized` at once, not retried.
 * - Scoped request, other failures: retried for `sourceFailureTimeoutMs`, then
 *   reported as `failed`. The poller then closes the scope, ending the request.
 * - Unscoped request (the active-patient poll): retried indefinitely.
 */
export function createUmaProxyFetch(options: UmaProxyFetchOptions = {}): UmaProxyFetch {
  const policy = options.policy ?? DEFAULT_FETCH_POLICY;
  const scopes = options.scopes;
  const fetchImpl = options.fetchImpl ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const egressUrl = options.egressUrl ?? (() => process.env.EGRESS_UMA_URL);
  const random = options.random ?? Math.random;
  const now = options.now ?? Date.now;
  const gates = new Map<string, HostGate>();
  let nextFetchID = 1;

  const gateFor = (host: string): HostGate => {
    let gate = gates.get(host);
    if (!gate) {
      gate = new HostGate(
        host,
        policy,
        (event, fields) => fetchLog("warn", "gate", event, fields),
        now,
        random,
      );
      gates.set(host, gate);
    }
    return gate;
  };

  return async function umaProxyFetch(input, init, authMode = "auto") {
    const originalUrl = input instanceof Request ? input.url : input.toString();
    const requestID = `f-${nextFetchID++}`;
    const targetDescription = describeFetchTarget(originalUrl);
    const startedAt = now();
    let lastFailure = "";
    let suppressedFailures = 0;

    const acceptHeader = init?.headers ? new Headers(init.headers).get("Accept") : undefined;
    const isStream = acceptHeader === "text/event-stream";
    const method = init?.method || "GET";

    const callerSignal = init?.signal ?? undefined;
    const scopeSignal = scopes?.signalFor(originalUrl);
    const signals = [callerSignal, scopeSignal].filter((s): s is AbortSignal => !!s);
    const signal = signals.length > 0 ? AbortSignal.any(signals) : new AbortController().signal;
    const gate = gateFor(hostKey(originalUrl));
    // Only requests for an active source scope report outcomes and give up.
    // Everything else, such as the active-patient poll, retries indefinitely.
    const scoped = scopeSignal !== undefined && !scopeSignal.aborted;
    let failingSince: number | undefined;
    let lastReason = "";
    let reported = false;
    let giveUpTimer: ReturnType<typeof setTimeout> | undefined;
    const reportFailure = (event: "unauthorized" | "failed", reason: string) => {
      if (!scoped || reported) return;
      reported = true;
      fetchLog("warn", requestID, event === "unauthorized" ? "unauthorized" : "gave-up", {
        reason,
        failing_ms: failingSince === undefined ? undefined : now() - failingSince,
        pod: targetDescription.pod,
        slice: targetDescription.slice,
      });
      scopes!.report(originalUrl, event, reason);
    };
    // The failure time limit also covers time spent waiting for a retry or for
    // an open breaker, so it is enforced by a timer as well as after attempts.
    const startFailing = (reason: string) => {
      lastReason = reason;
      failingSince ??= now();
      if (!scoped || reported || giveUpTimer) return;
      const remaining = Math.max(0, policy.sourceFailureTimeoutMs - (now() - failingSince));
      giveUpTimer = setTimeout(() => reportFailure("failed", lastReason), remaining);
      giveUpTimer.unref?.();
    };

    const stop = (attempts: number): Response => {
      if (callerSignal?.aborted) throw callerSignal.reason;
      fetchLog("info", requestID, "cancelled", {
        attempts,
        duration_ms: now() - startedAt,
        pod: targetDescription.pod,
        slice: targetDescription.slice,
      });
      return cancelledResponse(isStream, originalUrl);
    };

    fetchLog("info", requestID, "start", {
      method,
      auth: authMode,
      stream: isStream,
      pod: targetDescription.pod,
      slice: targetDescription.slice,
      target: targetDescription.pod ? undefined : targetDescription.target,
    });

    // `dispatcher` is an undici extension that RequestInit does not declare.
    const dispatch = isStream ? ({ dispatcher: streamDispatcher } as RequestInit) : {};

    const send = (): Promise<Response> => {
      const egress = egressUrl()?.replace(/\/+$/, "");
      if (!egress) {
        fetchLog("debug", requestID, "dispatch", { via: "direct" });
        return fetchImpl(input, { ...init, ...dispatch, signal });
      }
      fetchLog("debug", requestID, "dispatch", { via: "egress-uma" });
      const bodyHeaders = headerRecord(init?.headers);
      if (isStream) {
        bodyHeaders["Accept"] = "text/event-stream";
        bodyHeaders["Cache-Control"] = "no-cache";
        bodyHeaders["Connection"] = "keep-alive";
      }
      return fetchImpl(egress + "/fetch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": requestID,
        },
        body: JSON.stringify({
          url: originalUrl,
          method,
          headers: bodyHeaders,
          body: init?.body ? init.body.toString() : "",
          authMode,
        }),
        ...dispatch,
        // Closing this connection also cancels egress-uma's upstream request.
        signal,
      });
    };

    try {
      for (let attempt = 0; ; attempt++) {
        const attemptNumber = attempt + 1;
        if (signal.aborted) return stop(attempt);

        let permit: HostPermit;
        try {
          permit = await gate.enter(
            signal,
            () => startFailing(lastReason || `circuit breaker open for ${hostKey(originalUrl)}`),
            !isStream,
          );
        } catch {
          return stop(attempt);
        }

        try {
          const upstream = await send();

          if (!upstream.ok) {
            const responseBody = await upstream.text();
            throw new FetchResponseError(
              upstream.status,
              fetchFailureReason(responseBody, upstream.statusText),
              parseRetryAfter(upstream.headers.get("Retry-After"), now()),
            );
          }

          let response: Response;
          if (isStream) {
            // Streams hold no slot; this only records the outcome for the breaker.
            permit.done("success");
            response = guardStream(upstream, signal, originalUrl, (reason) => {
              fetchLog("warn", requestID, "stream-ended", {
                reason,
                pod: targetDescription.pod,
                slice: targetDescription.slice,
              });
              // The subscription will not resume by itself; let the poller re-add it.
              if (scoped) scopes!.report(originalUrl, "failed", reason);
            });
          } else {
            const text = NULL_BODY_STATUSES.has(upstream.status) ? null : await upstream.text();
            permit.done("success");
            response = withURL(
              new Response(text, {
                status: upstream.status,
                statusText: upstream.statusText,
                headers: upstream.headers,
              }),
              originalUrl,
            );
          }

          fetchLog("info", requestID, isStream ? "connected" : "complete", {
            status: upstream.status,
            attempt: attemptNumber,
            duration_ms: now() - startedAt,
            recovered: attempt > 0 || undefined,
            suppressed_failures: suppressedFailures || undefined,
          });
          if (scoped) scopes!.report(originalUrl, "success");
          return response;
        } catch (error) {
          const status = error instanceof FetchResponseError ? error.status : undefined;
          const retryAfterMs = error instanceof FetchResponseError ? error.retryAfterMs : undefined;
          const failure = classifyFailure(status);
          // An aborted attempt says nothing about the host's health.
          permit.done(signal.aborted ? "aborted" : failure, retryAfterMs);
          if (signal.aborted) return stop(attemptNumber);

          const reason = error instanceof FetchResponseError ? error.reason : (error as Error).message;
          if (failure === "auth") {
            // Unauthorized is not retried: the poller re-adds the source later.
            reportFailure("unauthorized", reason);
          } else {
            startFailing(reason);
            if (now() - failingSince! >= policy.sourceFailureTimeoutMs) reportFailure("failed", reason);
          }
          // After a report the poller closes the scope, which ends this request.
          // The slow delay is only a safety net in case that never happens.
          const delay = reported
            ? Math.max(policy.slowRetryDelayMs, retryDelay(attempt, failure, policy, retryAfterMs, random))
            : retryDelay(attempt, failure, policy, retryAfterMs, random);
          const signature = `${status ?? "network"}:${reason}`;
          const changed = signature !== lastFailure;
          if (reported) {
            // reportFailure already logged why this source is being given up.
          } else if (shouldLogFetchFailure(attemptNumber, changed)) {
            fetchLog("warn", requestID, failure === "auth" ? "denied" : "retry", {
              attempt: attemptNumber,
              status,
              class: failure,
              reason,
              retry_in_ms: delay,
              retry_after_ms: retryAfterMs,
              suppressed: suppressedFailures || undefined,
            });
            suppressedFailures = 0;
          } else {
            suppressedFailures++;
          }
          lastFailure = signature;

          try {
            await sleep(delay, signal);
          } catch {
            return stop(attemptNumber);
          }
        }
      }
    } finally {
      clearTimeout(giveUpTimer);
    }
  };
}

/** Scopes for pod slice sources; opened and closed by the active-patient poller. */
export const sourceFetchScopes = new FetchScopes();

export const umaProxyFetch = createUmaProxyFetch({
  policy: fetchPolicyFromEnv(),
  scopes: sourceFetchScopes,
});
