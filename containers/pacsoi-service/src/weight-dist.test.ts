import assert from "node:assert/strict";
import test from "node:test";
import { WeightDistribution } from "./weight-dist.js";

test("weight deletions remove the exact observation", () => {
  const dist = new WeightDistribution();
  dist.addPatientIdentifier("patient-1");
  dist.addPatientProcedure("patient-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("patient-1", "weight-1", 110, new Date("2026-09-30T08:00:00Z"));
  dist.addWeightObservation("patient-1", "weight-2", 90, new Date("2026-10-07T08:00:00Z"));

  assert.equal(dist.getStats()[-1]?.count, 1);
  assert.equal(dist.getStats()[0]?.count, 1);

  dist.removeWeightObservation("patient-1", "weight-1");
  assert.equal(dist.getStats()[-1], undefined);
  assert.equal(dist.getStats()[0]?.count, 1);
});

test("procedure deletions re-bucket retained observations", () => {
  const dist = new WeightDistribution();
  dist.addPatientIdentifier("patient-1");
  dist.addPatientProcedure("patient-1", "procedure-late", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("patient-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  assert.equal(dist.getStats()[0]?.count, 1);

  dist.addPatientProcedure("patient-1", "procedure-early", new Date("2026-09-04T00:00:00Z"));
  assert.equal(dist.getStats()[0], undefined);
  assert.equal(dist.getStats()[1]?.count, 1);

  dist.removePatientProcedure("patient-1", "procedure-early");
  assert.equal(dist.getStats()[1], undefined);
  assert.equal(dist.getStats()[0]?.count, 1);

  dist.removePatientProcedure("patient-1", "procedure-late");
  assert.deepEqual(dist.getStats(), {});
});

test("event deletion still works after its pseudo identifier is unlinked", () => {
  const dist = new WeightDistribution();
  dist.addPatientIdentifier("patient-1", "pseudo-1", "issuer-1");
  dist.addPatientProcedure("pseudo-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("pseudo-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  assert.equal(dist.getStats()[0]?.count, 1);

  dist.removePatientIdentifier("patient-1", "pseudo-1", "issuer-1");
  dist.removeWeightObservation("pseudo-1", "weight-1");
  assert.deepEqual(dist.getStats(), {});
});

test("patient count only includes patients contributing a weight", () => {
  const dist = new WeightDistribution();
  dist.addPatientIdentifier("patient-1", "pseudo-1", "issuer-1");
  dist.addPatientIdentifier("patient-2");
  dist.addPatientIdentifier("patient-3");
  dist.addPatientProcedure("patient-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("pseudo-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  dist.addWeightObservation("patient-1", "weight-2", 88, new Date("2026-11-07T08:00:00Z"));
  dist.addWeightObservation("patient-2", "weight-3", 100, new Date("2026-10-07T08:00:00Z"));
  assert.equal(dist.patientCount(), 1);

  dist.addPatientProcedure("patient-2", "procedure-2", new Date("2026-10-01T00:00:00Z"));
  assert.equal(dist.patientCount(), 2);

  dist.removePatient("patient-1");
  assert.equal(dist.patientCount(), 1);
});

test("re-sent observations and procedures are counted once", () => {
  const dist = new WeightDistribution();
  dist.addPatientIdentifier("patient-1");
  dist.addPatientProcedure("patient-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addPatientProcedure("patient-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("patient-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  dist.addWeightObservation("patient-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  assert.equal(dist.getStats()[0]?.count, 1);

  // Buffered duplicates for a not yet known identifier are dropped too.
  dist.addWeightObservation("pseudo-2", "weight-2", 80, new Date("2026-10-08T08:00:00Z"));
  dist.addWeightObservation("pseudo-2", "weight-2", 80, new Date("2026-10-08T08:00:00Z"));
  dist.addPatientIdentifier("patient-1", "pseudo-2", "issuer");
  assert.equal(dist.getStats()[0]?.count, 2);
});

test("clearPatientData drops weight data but keeps the identity", () => {
  const dist = new WeightDistribution();
  dist.addPatientIdentifier("patient-1", "pseudo-1", "issuer");
  dist.addPatientProcedure("pseudo-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("pseudo-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  dist.addPatientIdentifier("patient-2");
  dist.addPatientProcedure("patient-2", "procedure-2", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("patient-2", "weight-2", 100, new Date("2026-10-07T08:00:00Z"));
  assert.equal(dist.getStats()[0]?.count, 2);

  dist.clearPatientData("patient-1");
  assert.equal(dist.getStats()[0]?.count, 1);
  assert.equal(dist.patientCount(), 1);

  // The re-added sources replay the data; the pseudo identifier still resolves.
  dist.addPatientProcedure("pseudo-1", "procedure-1", new Date("2026-10-04T00:00:00Z"));
  dist.addWeightObservation("pseudo-1", "weight-1", 90, new Date("2026-10-07T08:00:00Z"));
  assert.equal(dist.getStats()[0]?.count, 2);
  assert.equal(dist.patientCount(), 2);
});
