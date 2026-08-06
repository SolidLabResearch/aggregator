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
  procedureTs: Date;
  responses: Map<string, ResponseBuffer>;
  monthlyScores: Map<number, number[]>;
}

interface MonthStats {
  mean: number;
  stdev: number;
  q25: number;
  q75: number;
  count: number;
}

class OxfordScoreDistribution {
  private patients = new Map<string, PatientData>();
  private preProcedureBuffer = new Map<string, Map<string, ResponseBuffer>>();

  // monthSinceProcedure -> list of scores (across all patients)
  private monthly = new Map<number, number[]>();

  // ================================
  // Input
  // ================================

  addPatientProcedure(patientID: string, timestamp: Date) {
    console.log(`[addPatientProcedure] Adding procedure for patient ${patientID} at ${timestamp.toISOString()}`);
    const existing = this.patients.get(patientID);

    if (!existing || timestamp <= existing.procedureTs) {
      this.patients.set(patientID, {
        procedureTs: timestamp,
        responses: new Map<string, ResponseBuffer>(),
        monthlyScores: new Map<number, number[]>()
      });

      // Flush any buffered responses
      const buffered = this.preProcedureBuffer.get(patientID);
      if (buffered) {
        console.log(`[addPatientProcedure] Flushing ${buffered.size} buffered responses for patient ${patientID}`);
        for (const res of buffered.values()) {
          this.addResponse(patientID, res);
        }
        this.preProcedureBuffer.delete(patientID);
      }
    } else {
      console.log(`[addPatientProcedure] Procedure not added, existing procedure is earlier.`);
    }
  }

  addPartialAnswer(
    patientID: string,
    responseID: string,
    timestamp: Date,
    question: string,
    value: string
  ) {
    const patient = this.patients.get(patientID);

    if (!patient) {
      console.log(`[addPartialAnswer] No procedure yet for patient ${patientID}. Buffering response ${responseID} at ${timestamp.toISOString()}`);
      if (!this.preProcedureBuffer.has(patientID)) {
        this.preProcedureBuffer.set(patientID, new Map<string, ResponseBuffer>());
      }
      if (!this.preProcedureBuffer.get(patientID)!.has(responseID)) {
        this.preProcedureBuffer.get(patientID)!.set(responseID, new ResponseBuffer(responseID, timestamp));
      }
      this.preProcedureBuffer.get(patientID)!.get(responseID)!.addAnswer(question, value);
      return;
    }

    if (!patient.responses.has(responseID)) {
      patient.responses.set(responseID, new ResponseBuffer(responseID, timestamp));
    }
    patient.responses.get(responseID)!.addAnswer(question, value);

    if (patient.responses.get(responseID)!.complete()) {
      this.addScore(patientID, patient.responses.get(responseID)!);
    }
  }

  private addResponse(patientID: string, res: ResponseBuffer) {
    if (!this.patients.has(patientID)) {
      throw new Error(`Cannot add response: ${patientID} not yet registered`);
    }

    if (res.complete()) {
      this.addScore(patientID, res);
    } else {
      const patient = this.patients.get(patientID)!;
      patient.responses.set(res.id, res);
    }
  }

  private addScore(patientID: string, res: ResponseBuffer) {
    if (!this.patients.has(patientID)) {
      throw new Error(`Cannot add score: ${patientID} not yet registered`);
    }

    const patient = this.patients.get(patientID)!;

    const month = this.monthsSince(patient.procedureTs, res.timestamp);

    if (!patient.monthlyScores.has(month)) {
      patient.monthlyScores.set(month, []);
    }
    patient.monthlyScores.get(month)!.push(res.getScore());

    if (!this.monthly.has(month)) {
      this.monthly.set(month, []);
    }
    this.monthly.get(month)!.push(res.getScore());

    patient.responses.delete(res.id);

    console.log(`[addScore] Added score ${res.getScore()} for patient ${patientID}, month ${month}`);
  }

  // ================================
  // Stats
  // ================================

  getStats(): Record<number, MonthStats> {
    const result: Record<number, MonthStats> = {};

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

class ResponseBuffer {
  public timestamp: Date;
  public id: string;

  private answers = new Map<string, number>();

  constructor(id: string, timestamp: Date) {
    this.id = id;
    this.timestamp = timestamp;
  }

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

  private resolveQuestionCode(question: string): string | undefined {
    for (const code of EXPECTED_QUESTIONS) {
      if (question.endsWith(code)) {
        return code;
      }
    }
    return undefined;
  }

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