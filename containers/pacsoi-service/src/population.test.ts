import assert from "node:assert/strict";
import test from "node:test";
import { PopulationStatus } from "./population.js";

test("population counts group statuses of active patients only", () => {
  const population = new PopulationStatus(() => new Date("2026-10-15T12:00:00Z"));
  assert.deepEqual(population.snapshot().lastPoll, null);

  population.pollSucceeded(["a", "b", "c"]);
  for (const patient of ["a", "b", "c"]) population.set(patient, "patient", "ok");
  population.set("a", "weight", "ok");
  population.set("b", "weight", "unauthorized");
  population.set("c", "weight", "failed");
  population.set("c", "bariatric", "stopped");

  let snapshot = population.snapshot();
  assert.equal(snapshot.activePatients, 3);
  assert.deepEqual(snapshot.lastPoll, { at: "2026-10-15T12:00:00.000Z", ok: true });
  assert.deepEqual(snapshot.groups.patient, { ok: 3, connecting: 0, unauthorized: 0, failed: 0, stopped: 0 });
  assert.deepEqual(snapshot.groups.weight, { ok: 1, connecting: 0, unauthorized: 1, failed: 1, stopped: 0 });
  assert.deepEqual(snapshot.groups.bariatric, { ok: 0, connecting: 2, unauthorized: 0, failed: 0, stopped: 1 });

  population.pollFailed("timeout");
  snapshot = population.snapshot();
  assert.equal(snapshot.activePatients, 3, "a failed poll keeps the last population");
  assert.equal(snapshot.lastPoll?.ok, false);

  population.pollSucceeded(["a"]);
  snapshot = population.snapshot();
  assert.equal(snapshot.activePatients, 1);
  assert.deepEqual(snapshot.groups.weight, { ok: 1, connecting: 0, unauthorized: 0, failed: 0, stopped: 0 });
});
