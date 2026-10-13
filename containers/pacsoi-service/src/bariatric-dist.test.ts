import assert from "node:assert/strict";
import test from "node:test";
import {
  BariatricScoreDistribution,
  QUESTIONNAIRE_TIMEPOINTS,
} from "./bariatric-dist.js";
import { OWLQOL_QUESTIONS } from "./bariatric-scores.js";

const questionnaires = Object.entries(QUESTIONNAIRE_TIMEPOINTS).reduce(
  (result, [questionnaire, point]) => ({ ...result, [point]: questionnaire }),
  {} as Record<string, string>,
);

function addResponse(
  dist: BariatricScoreDistribution,
  patient: string,
  response: string,
  point: "preop" | "6w" | "3m" | "6m" | "1y",
  owlqolValue: number,
  bother: number,
): void {
  for (const question of OWLQOL_QUESTIONS) {
    dist.addPartialAnswer(
      patient,
      response,
      questionnaires[point],
      question,
      String(owlqolValue),
    );
  }
  for (let item = 1; item <= 20; item++) {
    dist.addPartialAnswer(
      patient,
      response,
      questionnaires[point],
      `WRSM${item}`,
      item === 1 ? "1" : "0",
    );
  }
  dist.addPartialAnswer(
    patient,
    response,
    questionnaires[point],
    "WRSM1a",
    String(bother),
  );
}

test("aggregates scores and publishes ordered CSV statistics", () => {
  const dist = new BariatricScoreDistribution();
  dist.addPatientIdentifier("patient-1");
  dist.addPatientIdentifier("patient-2");
  addResponse(dist, "patient-1", "preop-1", "preop", 0, 2);
  addResponse(dist, "patient-2", "preop-2", "preop", 6, 6);
  addResponse(dist, "patient-1", "six-weeks-1", "6w", 0, 1);

  assert.deepEqual(dist.getStats(), {
    preop: {
      owlqol: { avg: 50, median: 50, stddev: 50, q25: 25, q75: 75 },
      wrsmBother: { avg: 4, median: 4, stddev: 2, q25: 3, q75: 5 },
      count: 2,
    },
    "6w": {
      owlqol: { avg: 100, median: 100, stddev: 0, q25: 100, q75: 100 },
      wrsmBother: { avg: 1, median: 1, stddev: 0, q25: 1, q75: 1 },
      count: 1,
    },
  });

  const rows = dist.toCSV().split("\n");
  assert.match(rows[0], /^timepoint,owlqol_avg,owlqol_median,owlqol_stddev,owlqol_q25,owlqol_q75/);
  assert.equal(rows[1], "preop,50.00,50.00,50.00,25.00,75.00,4.00,4.00,2.00,3.00,5.00,2");
  assert.equal(rows[2], "6w,100.00,100.00,0.00,100.00,100.00,1.00,1.00,0.00,1.00,1.00,1");
});

test("buffers responses until the patient identity arrives and removes contributions", () => {
  const dist = new BariatricScoreDistribution();
  addResponse(dist, "patient-1", "response-1", "3m", 2, 3);
  assert.deepEqual(dist.getStats(), {});

  dist.addPatientIdentifier("patient-1");
  assert.equal(dist.getStats()["3m"]?.count, 1);

  dist.removePatient("patient-1");
  assert.deepEqual(dist.getStats(), {});
});

test("answer deletions retract and later restore a completed score", () => {
  const dist = new BariatricScoreDistribution();
  dist.addPatientIdentifier("patient-1");
  addResponse(dist, "patient-1", "response-1", "preop", 2, 3);
  assert.equal(dist.getStats().preop?.count, 1);

  dist.removePartialAnswer(
    "patient-1",
    "response-1",
    questionnaires.preop,
    "OWLQOL",
    "2",
  );
  assert.deepEqual(dist.getStats(), {});

  dist.addPartialAnswer(
    "patient-1",
    "response-1",
    questionnaires.preop,
    "OWLQOL",
    "2",
  );
  assert.equal(dist.getStats().preop?.count, 1);
});

test("answer deletion still works after its pseudo identifier is unlinked", () => {
  const dist = new BariatricScoreDistribution();
  dist.addPatientIdentifier("patient-1", "pseudo-1", "issuer-1");
  addResponse(dist, "pseudo-1", "response-1", "preop", 2, 3);
  assert.equal(dist.getStats().preop?.count, 1);

  dist.removePatientIdentifier("patient-1", "pseudo-1", "issuer-1");
  dist.removePartialAnswer(
    "pseudo-1",
    "response-1",
    questionnaires.preop,
    "OWLQOL",
    "2",
  );
  assert.deepEqual(dist.getStats(), {});
});

test("patient count only includes patients with a completed score", () => {
  const dist = new BariatricScoreDistribution();
  dist.addPatientIdentifier("patient-1");
  dist.addPatientIdentifier("patient-2");
  addResponse(dist, "patient-1", "preop-1", "preop", 0, 2);
  addResponse(dist, "patient-1", "six-weeks-1", "6w", 0, 1);
  assert.equal(dist.patientCount(), 1);

  addResponse(dist, "patient-2", "preop-2", "preop", 6, 6);
  assert.equal(dist.patientCount(), 2);

  dist.removePatient("patient-2");
  assert.equal(dist.patientCount(), 1);
});
