const EXPECTED_QUESTIONS = new Set([
  "OxHo0","OxHa1","OxHa2","OxFo3","OxAf4","OxHa5",
  "OxIf6","OxHa7","OxLa8","OxHa9","OxHa10","OxHa11"
]);

/**
 * Hardcoded from the "Mapping" sheet of the Oxford Knee Score questionnaire
 * export (export_69a80a64e897421309bf18c0_2026-03-04.xlsx).
 */
const VALUE_MAP = new Map<string, Map<string, number>>([
  ["OxHo0", new Map([
    ["None", 0],
    ["Very mild", 1],
    ["Mild", 2],
    ["Moderate", 3],
    ["Severe", 4],
  ])],
  ["OxHa1", new Map([
    ["No trouble at all", 0],
    ["Very little trouble", 1],
    ["Moderate trouble", 2],
    ["Extreme difficulty", 3],
    ["Impossible to do", 4],
  ])],
  ["OxHa2", new Map([
    ["No trouble at all", 0],
    ["Very little trouble", 1],
    ["Moderate trouble", 2],
    ["Extreme difficulty", 3],
    ["Impossible to do", 4],
  ])],
  ["OxFo3", new Map([
    ["No pain, even after more than 30 minutes", 0],
    ["16-30 minutes", 1],
    ["5-15 minutes", 2],
    ["Around the house only", 3],
    ["Unable to walk at all", 4],
  ])],
  ["OxAf4", new Map([
    ["Not at all painful", 0],
    ["Slightly painful", 1],
    ["Moderately painful", 2],
    ["Very painful", 3],
    ["Unbearable", 4],
  ])],
  ["OxHa5", new Map([
    ["Rarely/never", 0],
    ["Sometimes or just at first", 1],
    ["Often, not just at first", 2],
    ["Most of the time", 3],
    ["All of the time", 4],
  ])],
  ["OxIf6", new Map([
    ["Yes, easily", 0],
    ["With little difficulty", 1],
    ["With moderate difficulty", 2],
    ["With extreme difficulty", 3],
    ["No, impossible", 4],
  ])],
  ["OxHa7", new Map([
    ["No nights", 0],
    ["Only 1 or 2 nights", 1],
    ["Some nights", 2],
    ["Most nights", 3],
    ["Every night", 4],
  ])],
  ["OxLa8", new Map([
    ["Not at all", 0],
    ["A little bit", 1],
    ["Moderately", 2],
    ["Greatly", 3],
    ["Totally", 4],
  ])],
  ["OxHa9", new Map([
    ["Rarely/never", 0],
    ["Sometimes or just at first", 1],
    ["Often, not just at first", 2],
    ["Most of the time", 3],
    ["All of the time", 4],
  ])],
  ["OxHa10", new Map([
    ["Yes, easily", 0],
    ["With little difficulty", 1],
    ["With moderate difficulty", 2],
    ["With extreme difficulty", 3],
    ["No, impossible", 4],
  ])],
  ["OxHa11", new Map([
    ["Yes, easily", 0],
    ["With little difficulty", 1],
    ["With moderate difficulty", 2],
    ["With extreme difficulty", 3],
    ["No, impossible", 4],
  ])],
]);

interface PatientData {
  identifiers: string[];
  procedureTs: Date | undefined;
  responses: Map<string, ResponseBuffer>;
  monthlyScores: Map<number, number[]>;
}

/** Aggregate statistics returned for a single relative calendar month. */
export interface OxfordDistributionStats {
  mean: number;
  stdev: number;
  q25: number;
  q75: number;
  count: number;
}

/**
 * In-memory projection of Oxford Knee Scores relative to knee procedures.
 *
 * Answers, procedures, and identifiers may arrive in any order. Incomplete
 * questionnaire responses remain buffered until all 12 expected answers are
 * present. Calls must be protected by the Oxford mutex owned by index.ts.
 */
class OxfordScoreDistribution {
  private identifiers = new Map<string, string>();
  private patients = new Map<string, PatientData>();
  private monthly = new Map<number, number[]>();
  private procedureBuffer = new Map<string, Date>();
  private responseBuffer = new Map<string, Map<string, ResponseBuffer>>();

  // ================================
  // Public API
  // ================================
  /** Registers the canonical patient URI and, optionally, a pseudo identifier. */
  addPatientIdentifier(patientID: string, identifier?: string) {
    const existing = this.patients.get(patientID);
    if (!existing) {
      console.log(`[addPatientIdentifier] Adding new patient ${patientID}`);
      this.patients.set(patientID, {
        identifiers: [patientID],
        procedureTs: undefined,
        responses: new Map<string, ResponseBuffer>(),
        monthlyScores: new Map<number, number[]>(),
      });
      this.identifiers.set(patientID, patientID);
    }

    if (identifier) {
      console.log(`[addPatientIdentifier] Adding external identifier ${identifier} for patient ${patientID}`);
      this.identifiers.set(identifier, patientID);
      this.patients.get(patientID)!.identifiers.push(identifier);
    }

    this.flushProcedures(patientID);
    // TODO only flush responses for this identifier
    this.flushResponses(patientID);
  }

  /** Records the first knee procedure observed, buffering if the patient is unknown. */
  addPatientProcedure(identifier: string, timestamp: Date) {
    console.log(`[addPatientProcedure] Recieved procedure for ID ${identifier} at ${timestamp.toISOString()}`);
    const patientID = this.identifiers.get(identifier);
    if (!patientID) {
      console.log(`[addPatientProcedure] No data yet for ID ${identifier}. Buffering procedure at ${timestamp.toISOString()}`);
      const buffer = this.procedureBuffer.get(identifier);
      if (!buffer) this.procedureBuffer.set(identifier, timestamp);
      else
        console.warn(`[addPatientProcedure] ID ${identifier} already has a procedure. Skipping procedure at ${timestamp.toISOString()}`);
      return
    }

    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[addPatientProcedure] Patient ${patientID} has identifiers but no data. Skipping...`);
      return
    } else if (!data.procedureTs) {
      data.procedureTs = timestamp;
      console.log(`[addPatientProcedure] Set Procedure for patient ${patientID} at ${timestamp.toISOString()}`);
      this.flushResponses(patientID);
    } else {
      console.warn(`[addPatientProcedure] Patient ${patientID} already has a procedure. Skipping procedure at ${timestamp.toISOString()}`);
    }
  }

  /** Adds one answer and emits a score once its 12-answer response is complete. */
  addPartialAnswer(
    identifier: string,
    responseID: string,
    timestamp: Date,
    question: string,
    value: string
  ) {
    const bufferAnswer = (reason: string) => {
      console.log(
        `[addPartialAnswer] ${reason}. Buffering answer for ${question} from response ${responseID}`
      );

      if (!this.responseBuffer.has(identifier)) {
        this.responseBuffer.set(identifier, new Map<string, ResponseBuffer>());
      }

      if (!this.responseBuffer.get(identifier)!.has(responseID)) {
        this.responseBuffer.get(identifier)!.set(responseID, new ResponseBuffer(responseID, timestamp));
      }

      this.responseBuffer.get(identifier)!.get(responseID)!.addAnswer(question, value);
    };

    const patientID = this.identifiers.get(identifier);

    if (!patientID) {
      bufferAnswer(`No patient yet for ID ${identifier}`);
      return;
    }

    const data = this.patients.get(patientID);

    if (!data) {
      console.warn(
        `[addPartialAnswer] Patient ${patientID} has identifiers but no data. Skipping...`
      );
      return;
    }

    if (!data.procedureTs) {
      bufferAnswer(`No procedure yet for patient ${patientID}`);
      return;
    }

    // Check if response already encountered
    if (!data.responses.has(responseID)) {
      // create buffer for newly encountered responses
      data.responses.set(responseID, new ResponseBuffer(responseID, timestamp));
    }
    // Add partial answer to response buffer
    data.responses.get(responseID)!.addAnswer(question, value);

    // Check if response is complete
    if (data.responses.get(responseID)!.complete()) {
      // If response complete, add score
      this.addScore(patientID, data.responses.get(responseID)!);
    }
  }

  private addScore(patientID: string, res: ResponseBuffer) {
    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[addScore] Cannot add score: ${patientID} not yet registered`);
      return;
    }


    if (!data.procedureTs) {
      console.warn(`[addScore] Cannot add score: No procedure yet for patient ${patientID}`);
      return;
    }

    const month = this.monthsSince(data.procedureTs, res.timestamp);

    const patientMonthlyData = data.monthlyScores.get(month) ?? [];
    patientMonthlyData.push(res.getScore());
    data.monthlyScores.set(month, patientMonthlyData)

    const globalMonthlyData = this.monthly.get(month) ?? [];
    globalMonthlyData.push(res.getScore());
    this.monthly.set(month, globalMonthlyData);

    data.responses.delete(res.id);

    console.log(`[addScore] Added score ${res.getScore()} for patient ${patientID}, month ${month}`);
  }

  flushProcedures(patientID: string) {
    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[flushProcedures] Patient ${patientID} has no data. Skipping...`);
      return;
    }

    if (data.procedureTs) {
      console.log(`[flushProcedures] Patient ${patientID} already has a procedure. Skipping...`);
      return;
    }

    for (const identifier of data.identifiers) {
      const buffer = this.procedureBuffer.get(identifier);
      if (buffer) {
        console.log(`[flushProcedures] Set Procedure for patient ${patientID} at ${buffer.toISOString()}`);
        data.procedureTs = buffer;
        this.flushResponses(patientID);
        break;
      }
    }

    if (data.procedureTs) {
      for (const identifier of data.identifiers) {
        this.procedureBuffer.delete(identifier);
      }
    }
  }

  flushResponses(patientID: string) {
    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[flushResponses] Patient ${patientID} has no data. Skipping...`);
      return
    }
    if (!data.procedureTs) {
      console.log(`[flushObservations] Patient ${patientID} has no procedure yet. Skipping...`);
      return
    }

    // Check all the patients identifiers for available buffers
    for (const identifier of data.identifiers) {
      const buffer = this.responseBuffer.get(identifier);
      if (buffer) {
        for (const [responseID, responseBuffer] of buffer) {
          // patient did not have this responseID registered
          if (!data.responses.has(responseID)) {
            data.responses.set(responseID, responseBuffer);
          } else {
            // Merge answers from buffered response with registered response
            data.responses.get(responseID)!.merge(responseBuffer);
          }
          // If the newly added response buffer is complete, add the score
          if (data.responses.get(responseID)!.complete()) {
            this.addScore(patientID, data.responses.get(responseID)!);
          }
        }
      }
      this.responseBuffer.delete(identifier);
    }
  }

  /** Removes a patient and that patient's scores from every aggregate. */
  removePatient(patientID: string) {
    console.log(`[removePatient] Removing patient ${patientID}`);
    const patient = this.patients.get(patientID);
    if (!patient) {
      console.log(`[removePatient] Patient ${patientID} not found`);
      return;
    }

    // Remove buffers
    for (const identifier of patient.identifiers) {
      this.procedureBuffer.delete(identifier);
      this.responseBuffer.delete(identifier);
      this.identifiers.delete(identifier);
    }

    if (patient.procedureTs) {
      // Remove scores already included in the global month buckets.
      for (const [month, scores] of patient.monthlyScores) {
        const bucket = this.monthly.get(month);
        if (!bucket) continue;

        for (const score of scores) {
          const idx = bucket.indexOf(score);
          if (idx !== -1) bucket.splice(idx, 1);
        }
        if (bucket.length === 0) this.monthly.delete(month);
      }
    }

    // This must also happen when no procedure was seen; otherwise re-adding the
    // patient leaves a stale record without an identifier mapping.
    this.patients.delete(patientID);
    console.log(`[removePatient] Patient ${patientID} removed`);
  }

  // ================================
  // Stats
  // ================================

  /** Returns population statistics for every non-empty month bucket. */
  getStats(): Record<number, OxfordDistributionStats> {
    const result: Record<number, OxfordDistributionStats> = {};

    for (const [month, values] of this.monthly.entries()) {
      if (values.length === 0) continue;

      const sorted = [...values].sort((a, b) => a - b);

      result[month] = {
        mean: this.mean(values),
        stdev: this.stdev(values),
        q25: this.percentile(sorted, 0.25),
        q75: this.percentile(sorted, 0.75),
        count: values.length,
      };
    }

    console.log(`[getStats] Computed stats for ${Object.keys(result).length} months`);
    return result;
  }

  toCSV(): string {
    const lines = ["month,avg_score,stdev,q25,q75,count"];
    const stats = this.getStats();

    for (const month of Object.keys(stats).map(Number).sort((a, b) => a - b)) {
      const s = stats[month];
      lines.push(
        `${month},${s.mean.toFixed(2)},${s.stdev.toFixed(2)},${s.q25.toFixed(
          2
        )},${s.q75.toFixed(2)},${s.count}`
      );
    }

    console.log(`[toCSV] Generated CSV with ${lines.length - 1} data rows`);
    return lines.join("\n");
  }

  // ================================
  // Helpers
  // ================================

  private monthsSince(start: Date, end: Date): number {
    return (
      (end.getFullYear() - start.getFullYear()) * 12 +
      (end.getMonth() - start.getMonth())
    );
  }

  private mean(arr: number[]): number {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  private stdev(arr: number[]): number {
    const m = this.mean(arr);
    const variance =
      arr.reduce((sum, x) => sum + (x - m) ** 2, 0) / arr.length;
    return Math.sqrt(variance);
  }

  private percentile(sorted: number[], p: number): number {
    const idx = (sorted.length - 1) * p;
    const lower = Math.floor(idx);
    const upper = Math.ceil(idx);

    if (lower === upper) return sorted[lower];

    return (
      sorted[lower] +
      (sorted[upper] - sorted[lower]) * (idx - lower)
    );
  }
}

/** Collects and validates the 12 answers belonging to one questionnaire response. */
class ResponseBuffer {
  public timestamp: Date;
  public id: string;

  private answers = new Map<string, number>();

  constructor(id: string, timestamp: Date) {
    this.id = id;
    this.timestamp = timestamp;
  }

  /** Maps and stores one answer; malformed or duplicate answers fail loudly. */
  addAnswer(question: string, value: string) {
    const code = this.resolveQuestionCode(question);

    if (!code) {
      throw new Error(`Unexpected question: ${question}`);
    }
    if (this.answers.has(code)) {
      throw new Error(`Response ${this.id} already has answer for ${code}`);
    }
    const mapped = VALUE_MAP.get(code)?.get(value);
    if (mapped === undefined) {
      throw new Error(`No value mapping for question ${code} with value ${value}`);
    }

    this.answers.set(code, mapped);
  }

  merge(other: ResponseBuffer) {
    if (other.id !== this.id) {
      console.warn(
        `[ResponseBuffer.merge] Cannot merge response with ID ${other.id} (expected: ${this.id})`
      );
      return;
    }

    if (other.timestamp.getTime() !== this.timestamp.getTime()) {
      console.warn(
        `[ResponseBuffer.merge] Cannot merge response with timestamp ` +
        `${other.timestamp.toISOString()} (expected: ${this.timestamp.toISOString()})`
      );
      return;
    }

    // Check for conflicts before modifying anything
    for (const [code, value] of other.answers) {
      const existing = this.answers.get(code);

      if (existing !== undefined && existing !== value) {
        console.warn(
          `[ResponseBuffer.merge] Cannot merge response: conflicting value ` +
          `for ${code}: ${existing} vs ${value}`
        );
        return;
      }
    }

    // Safe to merge
    for (const [code, value] of other.answers) {
      this.answers.set(code, value);
    }
  }

  private resolveQuestionCode(question: string): string | undefined {
    for (const code of EXPECTED_QUESTIONS) {
      if (question.endsWith(code)) {
        return code;
      }
    }
    return undefined;
  }

  /** Returns the 0-48 Oxford Knee Score (higher is better). */
  getScore(): number {
    let sum = 0;
    for (const x of this.answers.values()) {
      sum += 4 - x;
    }
    return sum;
  }

  complete(): boolean {
    return this.answers.size === EXPECTED_QUESTIONS.size;
  }
}

export { OxfordScoreDistribution, ResponseBuffer };
