import assert from "node:assert/strict";
import test from "node:test";
import { BariatricScoreBuffer, OWLQOL_QUESTIONS } from "./bariatric-scores.js";

test("scores the supplied combined questionnaire response", () => {
  const response = new BariatricScoreBuffer("response-1");
  const owlqolValues = [3, 1, 2, 1, 2, 2, 2, 6, 3, 3, 3, 3, 4, 6, 2, 2, 1];

  [...OWLQOL_QUESTIONS].forEach((question, index) => {
    response.addAnswer(
      `https://moveup.care/Question/${question}`,
      String(owlqolValues[index]),
    );
  });

  for (let item = 1; item <= 20; item++) {
    response.addAnswer(
      `https://moveup.care/Question/WRSM${item}`,
      item === 20 ? "1" : "0",
    );
  }
  response.addAnswer("https://moveup.care/Question/WRSM20b", "6");
  assert.equal(
    response.addAnswer("https://moveup.care/Question/BAROSQOL1", "25.0"),
    false,
  );

  assert.equal(response.complete(), true);
  const scores = response.getScores();
  assert.ok(Math.abs(scores.owlqol - 54.90196078431373) < 1e-12);
  assert.equal(scores.wrsmBother, 6);
});

test("requires a bother answer only for symptoms that are present", () => {
  const response = new BariatricScoreBuffer("response-2");
  for (const question of OWLQOL_QUESTIONS) response.addAnswer(question, "0");
  for (let item = 1; item <= 20; item++) {
    response.addAnswer(`WRSM${item}`, item === 3 ? "1" : "0");
  }

  assert.equal(response.complete(), false);
  response.addAnswer("WRSM3b", "4");
  assert.deepEqual(response.getScores(), {
    owlqol: 100,
    wrsmBother: 4,
  });
});

test("rejects invalid questionnaire values", () => {
  const response = new BariatricScoreBuffer("response-3");
  assert.throws(() => response.addAnswer("OWLQOL", "7"), /expected an integer/);
  assert.throws(() => response.addAnswer("WRSM1", "2"), /expected an integer/);
  assert.throws(() => response.addAnswer("WRSM21", "0"), /Unexpected WRSM item/);
  assert.throws(() => response.addAnswer("WRSM1c", "0"), /Unexpected bariatric question/);
});

test("uses unsuffixed WRSM answers for presence and the modeled suffix for bother", () => {
  const response = new BariatricScoreBuffer("response-bother-suffixes");
  for (const question of OWLQOL_QUESTIONS) response.addAnswer(question, "0");
  for (let item = 1; item <= 20; item++) {
    response.addAnswer(`WRSM${item}`, item === 1 || item === 3 ? "1" : "0");
  }
  response.addAnswer("WRSM1a", "3");
  response.addAnswer("WRSM3b", "4");

  assert.deepEqual(response.getScores(), {
    owlqol: 100,
    wrsmBother: 7,
  });

  assert.equal(response.removeAnswer("WRSM1a", "3"), true);
  assert.equal(response.complete(), false);
});

test("rejects suffixes that do not match the WRSM source model", () => {
  const response = new BariatricScoreBuffer("response-wrong-suffix");
  assert.throws(() => response.addAnswer("WRSM1b", "2"), /expected WRSM1a/);
  assert.throws(() => response.addAnswer("WRSM2b", "2"), /expected WRSM2a/);
  assert.throws(() => response.addAnswer("WRSM3a", "2"), /expected WRSM3b/);
});

test("rejects a non-zero bother score for an absent symptom", () => {
  const response = new BariatricScoreBuffer("response-4");
  for (const question of OWLQOL_QUESTIONS) response.addAnswer(question, "0");
  for (let item = 1; item <= 20; item++) response.addAnswer(`WRSM${item}`, "0");
  response.addAnswer("WRSM1a", "2");

  assert.throws(() => response.getScores(), /absent but has a non-zero bother/);
});
