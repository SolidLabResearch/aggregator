const VALUE_MAP = new Map<string, Map<string, number>>();
const EXPECTED_QUESTIONS = new Set([
  "OxHo0","OxHa1","OxHa2","OxFo3","OxAf4","OxHa5",
  "OxIf6","OxHa7","OxLa8","OxHa9","OxHa10","OxHa11"
]);

interface PatientData {
  procedureTs: Date;
  responses: Map<string, ResponseBuffer>;
  monthlyScores: Map<number, number[]>;
}

class OxfordScoreDistribution {
  private patients = new Map<string, PatientData>();
  private preProcedureBuffer = new Map<string, Map<string, ResponseBuffer>>();

  // responses waiting to be completed
  private responseBuffers = new Map<string, ResponseBuffer>();

  // responses waiting for procedure
  private pendingScores: Array<{
    patientId: string;
    timestamp: number;
    score: number;
  }> = [];

  // final aggregation:
  // monthSinceProcedure -> patientId -> list of scores
  private distribution = new Map<number, Map<string, number[]>>();

  private valueMaps = new Map<string, Map<string, number>>();

  constructor(config: any[]) {
    this.initValueMaps(config);
  }

  // ================================
  // Init
  // ================================

  private initValueMaps(config: any[]) {
    for (const q of config) {
      const map = new Map<string, number>();
      for (const v of q.valueMap) {
        map.set(v.label, Number(v.score));
      }
      this.valueMaps.set(q.code, map);
    }
  }

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
      } else {
        console.log(`[addPatientProcedure] Procedure not added, existing procedure is earlier.`);
      }
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

    if (timestamp < patient.procedureTs) {
      console.log(`[addPartialAnswer] Response ${responseID} at ${timestamp.toISOString()} ignored, before procedure for patient ${patientID}`);
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

  addResponse(patientID: string, res: ResponseBuffer) {
    if (!this.patients.has(patientID)) {
      throw new Error(`Cannot add response: ${patientID} not yet registered`);
    }

    const patient = this.patients.get(patientID)!;

    if (res.timestamp < patient.procedureTs) {
      console.log(`[addResponse] Response ${res.id} at ${res.timestamp.toISOString()} ignored, before procedure for patient ${patientID}`);
      return;
    }

    if (res.complete()) {
      this.addScore(patientID, res);
    } else {
      patient.responses.set(res.id, res);
    }
  }

  addScore(patientID: string, res: ResponseBuffer) {
    if (!this.patients.has(patientID)) {
      throw new Error(`Cannot add score: ${patientID} not yet registered`);
    }

    const patient = this.patients.get(patientID)!;

    const month = this.monthsSince(patient.procedureTs, res.timestamp);
    if (!patient.monthlyScores.has(month)) {
      patient.monthlyScores.set(month, []);
    }
    patient.monthlyScores.get(month)!.push(res.getScore());
    patient.responses.delete(res.id);
  }

  // ================================
  // Stats
  // ================================

  getStats() {
    /*
    const result: Record<number, any> = {};

    for (const [month, { values }] of this.monthly.entries()) {
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
    */
  }

  toCSV(): string {
    /*
    const lines = ["month,avg_weight,stdev,q25,q75,count"];
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
    */
   return "";
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
    if (this.answers.has(question)) {
      throw new Error(`Response ${this.id} already has answer for ${question}`)
    }
    if (!EXPECTED_QUESTIONS.has(question)) {
      throw new Error(`Unexpected question: ${question}`);
    }
    if (!VALUE_MAP.get(question)?.has(value)) {
      throw new Error(`No value mapping for question ${question} with value ${value}`);
    }

    this.answers.set(question, VALUE_MAP.get(question)?.get(value)!);
  }

  getScore(): number {
    return Object.values(this.answers).reduce((sum, x) => sum += 4 - x, 0);
  }

  complete(): boolean {
    return this.answers.size === EXPECTED_QUESTIONS.size;
  }
}
