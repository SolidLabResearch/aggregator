import assert from "node:assert/strict";
import test from "node:test";
import {
  describeFetchTarget,
  parseActivePatients,
  PatientSourceOwnership,
  resolvePodURL,
  shouldLogFetchFailure,
} from "./query.js";

test("parseActivePatients validates, normalizes, and deduplicates the API response", () => {
  assert.deepEqual(
    parseActivePatients([
      { id: "patient-1", pod_id: "https://pod.example/patient-1/" },
      { id: "patient-1", pod_id: "https://pod.example/patient-1" },
      { id: "patient-2", pod_id: "https://pod.example/patient-2" },
    ]),
    [
      { id: "patient-1", pod_id: "https://pod.example/patient-1" },
      { id: "patient-2", pod_id: "https://pod.example/patient-2" },
    ],
  );
});

test("parseActivePatients rejects malformed entries", () => {
  assert.throws(
    () => parseActivePatients([{ id: "patient-1" }]),
    /must contain non-empty id and pod_id strings/,
  );
  assert.throws(
    () => parseActivePatients([{ id: "patient-1", pod_id: "https://one" }, { id: "patient-1", pod_id: "https://two" }]),
    /conflicting pods/,
  );
});

test("resolvePodURL expands pod identifiers and preserves absolute URLs", () => {
  assert.equal(
    resolvePodURL("andries-pacsoi300903", "https://pacsoi-kvasir.faqir.org"),
    "https://pacsoi-kvasir.faqir.org/andries-pacsoi300903",
  );
  assert.equal(
    resolvePodURL("https://other.example/patient/", "https://pacsoi-kvasir.faqir.org"),
    "https://other.example/patient",
  );
});

test("PatientSourceOwnership retains API and canonical IDs and rejects late events", () => {
  const ownership = new PatientSourceOwnership("https://pods.example/pod-1", "api-patient-1");

  assert.equal(ownership.track("canonical-patient-1"), true);
  assert.equal(ownership.track("canonical-patient-1"), true);
  assert.deepEqual(
    ownership.deactivate().sort(),
    ["api-patient-1", "canonical-patient-1"],
  );
  assert.equal(ownership.track("late-patient"), false);
  assert.deepEqual(
    ownership.deactivate().sort(),
    ["api-patient-1", "canonical-patient-1"],
  );
});

test("describeFetchTarget extracts pod and slice without query parameters", () => {
  assert.deepEqual(
    describeFetchTarget("https://kvasir.example/pod-1/slices/Read-Patient/query?token=secret"),
    {
      target: "https://kvasir.example/pod-1/slices/Read-Patient/query",
      pod: "pod-1",
      slice: "Read-Patient",
    },
  );
});

test("unchanged fetch failures are sampled at powers of two", () => {
  assert.deepEqual(
    [1, 2, 3, 4, 5, 8].map(attempt => shouldLogFetchFailure(attempt, false)),
    [true, true, false, true, false, true],
  );
  assert.equal(shouldLogFetchFailure(3, true), true);
});
