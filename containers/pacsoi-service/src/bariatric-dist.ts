import {
  BariatricQuestionnaireScores,
  BariatricScoreBuffer,
} from "./bariatric-scores.js";

export const BARIATRIC_TIMEPOINTS = ["preop", "6w", "3m", "6m", "1y"] as const;
export type BariatricTimepoint = (typeof BARIATRIC_TIMEPOINTS)[number];

export const QUESTIONNAIRE_TIMEPOINTS: Readonly<Record<string, BariatricTimepoint>> = {
  "https://moveup.care/Questionnaire/cX2u2njqWR8ErehW4": "preop",
  "https://moveup.care/Questionnaire/5fsdff4wqtzLEPqaQ": "6w",
  "https://moveup.care/Questionnaire/TpYG3bjxPT4QCwg9A": "3m",
  "https://moveup.care/Questionnaire/5cdZ4Qd7uWgSQ29B8": "6m",
  "https://moveup.care/Questionnaire/MDZj8qTHYXaEf3zDX": "1y",
};

interface BufferedResponse {
  timepoint: BariatricTimepoint;
  answers: BariatricScoreBuffer;
}

interface StoredScore extends BariatricQuestionnaireScores {
  responseID: string;
  timepoint: BariatricTimepoint;
}

interface PatientData {
  patientIDs: Set<string>;
  identifiers: Set<string>;
  responses: Map<string, BufferedResponse>;
  scores: Map<string, StoredScore>;
}

export interface MetricStats {
  avg: number;
  median: number;
  stddev: number;
  q25: number;
  q75: number;
}

export interface BariatricDistributionStats {
  owlqol: MetricStats;
  wrsmBother: MetricStats;
  count: number;
}

/**
 * In-memory projection of completed bariatric questionnaire scores at the five
 * clinical follow-up points. Calls are serialized by the mutex in index.ts.
 */
export class BariatricScoreDistribution {
  private nextRecordID = 1;
  private readonly identifiers = new Map<string, string>();
  private readonly issuedIdentifiers = new Map<string, string>();
  private readonly patients = new Map<string, PatientData>();
  private readonly pendingResponses = new Map<string, Map<string, BufferedResponse>>();
  private readonly scores = new Map<BariatricTimepoint, StoredScore[]>();

  addPatientIdentifier(patientID: string, identifier?: string, issuer?: string): void {
    let recordID = this.identifiers.get(patientID);
    if (!recordID) {
      recordID = `record-${this.nextRecordID++}`;
      this.patients.set(recordID, {
        patientIDs: new Set([patientID]),
        identifiers: new Set([patientID]),
        responses: new Map(),
        scores: new Map(),
      });
      this.identifiers.set(patientID, recordID);
    }

    if (identifier) {
      if (!issuer) {
        console.warn(`[BariatricScoreDistribution] Ignoring identifier ${identifier} without issuer`);
      } else {
        const identityKey = JSON.stringify([issuer, identifier]);
        const matchingRecordID = this.issuedIdentifiers.get(identityKey);
        if (matchingRecordID && matchingRecordID !== recordID) {
          recordID = this.mergeRecords(recordID, matchingRecordID);
        }

        const patient = this.patients.get(recordID)!;
        patient.patientIDs.add(patientID);
        patient.identifiers.add(identifier);
        this.identifiers.set(patientID, recordID);
        this.identifiers.set(identifier, recordID);
        this.issuedIdentifiers.set(identityKey, recordID);
      }
    }

    this.flushPendingResponses(recordID);
  }

  addPartialAnswer(
    identifier: string,
    responseID: string,
    questionnaireID: string,
    question: string,
    value: string,
  ): void {
    const timepoint = QUESTIONNAIRE_TIMEPOINTS[questionnaireID];
    if (!timepoint) {
      throw new Error(`Unexpected bariatric questionnaire: ${questionnaireID}`);
    }

    const recordID = this.identifiers.get(identifier) ?? this.findRecordByResponse(responseID);
    if (!recordID) {
      const responses = this.pendingResponses.get(identifier) ?? new Map();
      const response = this.getOrCreateResponse(responses, responseID, timepoint);
      response.answers.addAnswer(question, value);
      this.pendingResponses.set(identifier, responses);
      return;
    }

    const patient = this.patients.get(recordID);
    if (!patient) throw new Error(`No bariatric patient record for ${recordID}`);

    const response = this.getOrCreateResponse(patient.responses, responseID, timepoint);
    response.answers.addAnswer(question, value);
    this.completeResponse(recordID, responseID);
  }

  removePartialAnswer(
    identifier: string,
    responseID: string,
    questionnaireID: string,
    question: string,
    value: string,
  ): void {
    const timepoint = QUESTIONNAIRE_TIMEPOINTS[questionnaireID];
    if (!timepoint) throw new Error(`Unexpected bariatric questionnaire: ${questionnaireID}`);

    const recordID = this.identifiers.get(identifier) ?? this.findRecordByResponse(responseID);
    const responses = recordID
      ? this.patients.get(recordID)?.responses
      : this.pendingResponses.get(identifier);
    const response = responses?.get(responseID);
    if (!response) return;
    if (response.timepoint !== timepoint) {
      throw new Error(`Response ${responseID} belongs to ${response.timepoint}, not ${timepoint}`);
    }

    const changed = response.answers.removeAnswer(question, value);
    if (!changed || !recordID) return;

    const patient = this.patients.get(recordID)!;
    const score = patient.scores.get(responseID);
    if (score) {
      this.removeScoreContribution(score);
      patient.scores.delete(responseID);
    }
    this.completeResponse(recordID, responseID);
  }

  removePatientIdentifier(patientID: string, identifier: string, issuer: string): void {
    const recordID = this.identifiers.get(patientID);
    const patient = recordID ? this.patients.get(recordID) : undefined;
    if (!recordID || !patient || identifier === patientID) return;

    patient.identifiers.delete(identifier);
    if (this.identifiers.get(identifier) === recordID) this.identifiers.delete(identifier);
    const identityKey = JSON.stringify([issuer, identifier]);
    if (this.issuedIdentifiers.get(identityKey) === recordID) this.issuedIdentifiers.delete(identityKey);
  }

  /**
   * Drops a patient's questionnaire responses and scores, including pending
   * ones, but keeps the patient's identity. Used when the questionnaire
   * sources are suspended; re-added sources replay the data from scratch.
   */
  clearPatientData(patientID: string): void {
    const recordID = this.identifiers.get(patientID);
    const patient = recordID ? this.patients.get(recordID) : undefined;
    if (!patient) return;
    this.removeScoreContributions(patient);
    patient.responses.clear();
    patient.scores.clear();
    for (const identifier of patient.identifiers) this.pendingResponses.delete(identifier);
  }

  removePatient(patientID: string): void {
    const recordID = this.identifiers.get(patientID);
    const patient = recordID ? this.patients.get(recordID) : undefined;
    if (!recordID || !patient) return;

    patient.patientIDs.delete(patientID);
    patient.identifiers.delete(patientID);
    this.identifiers.delete(patientID);
    this.pendingResponses.delete(patientID);
    if (patient.patientIDs.size > 0) return;

    this.removeScoreContributions(patient);
    for (const identifier of patient.identifiers) {
      this.identifiers.delete(identifier);
      this.pendingResponses.delete(identifier);
    }
    for (const [key, owner] of this.issuedIdentifiers) {
      if (owner === recordID) this.issuedIdentifiers.delete(key);
    }
    this.patients.delete(recordID);
  }

  /** Number of distinct patients contributing at least one completed score. */
  patientCount(): number {
    let count = 0;
    for (const patient of this.patients.values()) {
      if (patient.scores.size > 0) count++;
    }
    return count;
  }

  getStats(): Partial<Record<BariatricTimepoint, BariatricDistributionStats>> {
    const result: Partial<Record<BariatricTimepoint, BariatricDistributionStats>> = {};
    for (const timepoint of BARIATRIC_TIMEPOINTS) {
      const values = this.scores.get(timepoint) ?? [];
      if (values.length === 0) continue;
      result[timepoint] = {
        owlqol: this.metricStats(values.map(score => score.owlqol)),
        wrsmBother: this.metricStats(values.map(score => score.wrsmBother)),
        count: values.length,
      };
    }
    return result;
  }

  toCSV(): string {
    const lines = [
      "timepoint,owlqol_avg,owlqol_median,owlqol_stddev,owlqol_q25,owlqol_q75," +
        "wrsm_bother_avg,wrsm_bother_median,wrsm_bother_stddev,wrsm_bother_q25,wrsm_bother_q75,count",
    ];
    const stats = this.getStats();

    for (const timepoint of BARIATRIC_TIMEPOINTS) {
      const point = stats[timepoint];
      if (!point) continue;
      lines.push([
        timepoint,
        this.format(point.owlqol.avg),
        this.format(point.owlqol.median),
        this.format(point.owlqol.stddev),
        this.format(point.owlqol.q25),
        this.format(point.owlqol.q75),
        this.format(point.wrsmBother.avg),
        this.format(point.wrsmBother.median),
        this.format(point.wrsmBother.stddev),
        this.format(point.wrsmBother.q25),
        this.format(point.wrsmBother.q75),
        String(point.count),
      ].join(","));
    }

    return lines.join("\n");
  }

  private getOrCreateResponse(
    responses: Map<string, BufferedResponse>,
    responseID: string,
    timepoint: BariatricTimepoint,
  ): BufferedResponse {
    const existing = responses.get(responseID);
    if (existing) {
      if (existing.timepoint !== timepoint) {
        throw new Error(
          `Response ${responseID} belongs to both ${existing.timepoint} and ${timepoint}`,
        );
      }
      return existing;
    }

    const response = { timepoint, answers: new BariatricScoreBuffer(responseID) };
    responses.set(responseID, response);
    return response;
  }

  private findRecordByResponse(responseID: string): string | undefined {
    for (const [recordID, patient] of this.patients) {
      if (patient.responses.has(responseID)) return recordID;
    }
    return undefined;
  }

  private completeResponse(recordID: string, responseID: string): void {
    const patient = this.patients.get(recordID)!;
    const response = patient.responses.get(responseID);
    if (!response?.answers.complete() || patient.scores.has(responseID)) return;

    const score: StoredScore = {
      responseID,
      timepoint: response.timepoint,
      ...response.answers.getScores(),
    };
    patient.scores.set(responseID, score);
    const bucket = this.scores.get(score.timepoint) ?? [];
    bucket.push(score);
    this.scores.set(score.timepoint, bucket);
  }

  private flushPendingResponses(recordID: string): void {
    const patient = this.patients.get(recordID);
    if (!patient) return;
    for (const identifier of patient.identifiers) {
      const pending = this.pendingResponses.get(identifier);
      if (!pending) continue;
      for (const [responseID, response] of pending) {
        if (patient.scores.has(responseID)) continue;
        const existing = patient.responses.get(responseID);
        if (existing) {
          if (existing.timepoint !== response.timepoint) {
            throw new Error(`Conflicting timepoints for response ${responseID}`);
          }
          existing.answers.merge(response.answers);
        } else {
          patient.responses.set(responseID, response);
        }
        this.completeResponse(recordID, responseID);
      }
      this.pendingResponses.delete(identifier);
    }
  }

  private mergeRecords(firstID: string, secondID: string): string {
    const first = this.patients.get(firstID)!;
    const second = this.patients.get(secondID)!;
    const recordID = `record-${this.nextRecordID++}`;

    this.removeScoreContributions(first);
    this.removeScoreContributions(second);
    const responses = new Map(first.responses);
    for (const [responseID, response] of second.responses) {
      const existing = responses.get(responseID);
      if (existing) {
        if (existing.timepoint !== response.timepoint) {
          throw new Error(`Conflicting timepoints for response ${responseID}`);
        }
        existing.answers.merge(response.answers);
      } else {
        responses.set(responseID, response);
      }
    }

    const storedScores = new Map(first.scores);
    for (const [responseID, score] of second.scores) storedScores.set(responseID, score);
    const merged: PatientData = {
      patientIDs: new Set([...first.patientIDs, ...second.patientIDs]),
      identifiers: new Set([...first.identifiers, ...second.identifiers]),
      responses,
      scores: storedScores,
    };

    this.patients.delete(firstID);
    this.patients.delete(secondID);
    this.patients.set(recordID, merged);
    for (const identifier of merged.identifiers) this.identifiers.set(identifier, recordID);
    for (const [key, owner] of this.issuedIdentifiers) {
      if (owner === firstID || owner === secondID) this.issuedIdentifiers.set(key, recordID);
    }
    for (const score of merged.scores.values()) this.addScoreContribution(score);
    for (const responseID of [...merged.responses.keys()]) {
      this.completeResponse(recordID, responseID);
    }
    return recordID;
  }

  private addScoreContribution(score: StoredScore): void {
    const bucket = this.scores.get(score.timepoint) ?? [];
    bucket.push(score);
    this.scores.set(score.timepoint, bucket);
  }

  private removeScoreContributions(patient: PatientData): void {
    for (const score of patient.scores.values()) {
      this.removeScoreContribution(score);
    }
  }

  private removeScoreContribution(score: StoredScore): void {
    const bucket = this.scores.get(score.timepoint);
    if (!bucket) return;
    const index = bucket.findIndex(value => value.responseID === score.responseID);
    if (index !== -1) bucket.splice(index, 1);
    if (bucket.length === 0) this.scores.delete(score.timepoint);
  }

  private metricStats(values: number[]): MetricStats {
    const sorted = [...values].sort((a, b) => a - b);
    const avg = values.reduce((sum, value) => sum + value, 0) / values.length;
    const middle = Math.floor(sorted.length / 2);
    const median = sorted.length % 2 === 0
      ? (sorted[middle - 1] + sorted[middle]) / 2
      : sorted[middle];
    const variance = values.reduce((sum, value) => sum + (value - avg) ** 2, 0) / values.length;
    return {
      avg,
      median,
      stddev: Math.sqrt(variance),
      q25: this.percentile(sorted, 0.25),
      q75: this.percentile(sorted, 0.75),
    };
  }

  private percentile(sorted: number[], percentile: number): number {
    const index = (sorted.length - 1) * percentile;
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    if (lower === upper) return sorted[lower];
    return sorted[lower] * (upper - index) + sorted[upper] * (index - lower);
  }

  private format(value: number): string {
    return value.toFixed(2);
  }
}
