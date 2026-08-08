type WeightObservation = {
  value: number;
  timestamp: Date;
};

type PatientData = {
  identifiers: string[]
  procedureTs: Date | undefined;
  observations: WeightObservation[];
};

/** Aggregate statistics returned for a single relative calendar month. */
export type DistributionStats = {
  mean: number;
  stdev: number;
  q25: number;
  q75: number;
  count: number;
};

/**
 * In-memory projection of patient weights relative to bariatric procedures.
 *
 * Events can arrive out of order. Procedures and observations are therefore
 * buffered by any known identifier until the canonical patient and procedure
 * are available. All calls are expected to be protected by the mutex owned by
 * index.ts; this class does not perform its own locking.
 */
export class WeightDistribution {
  private identifiers = new Map<string, string>();
  private patients = new Map<string, PatientData>();
  private monthly = new Map<number, number[]>();
  private procedureBuffer = new Map<string, Date>();
  private observationsBuffer = new Map<string, WeightObservation[]>();

  // ================================
  // Public API
  // ================================
  /** Registers the canonical patient URI and, optionally, a pseudo identifier. */
  addPatientIdentifier(patientID: string, identifier?: string) {
    const existing = this.patients.get(patientID);
    if (!existing) {
      console.log(`[addPatientIdentifiers] Adding new patient ${patientID}`);
      this.patients.set(patientID, {
        identifiers: [patientID],
        procedureTs: undefined,
        observations: []
      });
      this.identifiers.set(patientID, patientID);
    }

    if (identifier) {
      console.log(`[addPatientIdentifier] Adding external identifier ${identifier} for patient ${patientID}`);
      this.identifiers.set(identifier, patientID);
      this.patients.get(patientID)!.identifiers.push(identifier);
    }

    this.flushProcedures(patientID);
    this.flushObservations(patientID);
  }

  /** Records the first procedure observed for a patient, buffering if unknown. */
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
      this.flushObservations(patientID);
    } else {
      console.warn(`[addPatientProcedure] Patient ${patientID} already has a procedure. Skipping procedure at ${timestamp.toISOString()}`);
    }
  }

  /** Adds a weight to its calendar-month bucket, buffering if prerequisites are missing. */
  addWeightObservation(identifier: string, value: number, timestamp: Date) {
    const observation = { value, timestamp };

    const bufferObservation = (reason: string) => {
      console.log(
        `[addWeightObservation] ${reason}. Buffering observation ${value} at ${timestamp.toISOString()}`
      );

      if (!this.observationsBuffer.has(identifier)) {
        this.observationsBuffer.set(identifier, []);
      }

      this.observationsBuffer.get(identifier)!.push(observation);
    };

    const patientID = this.identifiers.get(identifier);

    if (!patientID) {
      bufferObservation(`No patient yet for ID ${identifier}`);
      return;
    }

    const data = this.patients.get(patientID);

    if (!data) {
      console.warn(
        `[addWeightObservation] Patient ${patientID} has identifiers but no data. Skipping...`
      );
      return;
    }

    if (!data.procedureTs) {
      bufferObservation(`No procedure yet for patient ${patientID}`);
      return;
    }

    const month = this.monthsSince(data.procedureTs, timestamp);

    data.observations.push(observation);

    const monthlyData = this.monthly.get(month) ?? [];
    monthlyData.push(value);
    this.monthly.set(month, monthlyData);

    console.log(
      `[addWeightObservation] Added observation ${value} at ${timestamp.toISOString()} ` +
        `for patient ${patientID}, month ${month}`
    );
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
        this.flushObservations(patientID);
        break;
      }
    }

    if (data.procedureTs) {
      for (const identifier of data.identifiers) {
        this.procedureBuffer.delete(identifier);
      }
    }
  }

  flushObservations(patientID: string) {
    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[flushObservations] Patient ${patientID} has no data. Skipping...`);
      return
    }
    if (!data.procedureTs) {
      console.log(`[flushObservations] Patient ${patientID} has no procedure yet. Skipping...`);
      return
    }

    for (const identifier of data.identifiers) {
      const buffer = this.observationsBuffer.get(identifier);
      if (buffer) {
        for (const obs of buffer) {
          this.addWeightObservation(identifier, obs.value, obs.timestamp);
        }
        this.observationsBuffer.delete(identifier);
      }
    }
  }

  /** Removes a patient and that patient's contribution from every aggregate. */
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
      this.observationsBuffer.delete(identifier);
      this.identifiers.delete(identifier);
    }

    if (patient.procedureTs) {
      // Remove observations already included in the global month buckets.
      for (const obs of patient.observations) {
        const month = this.monthsSince(patient.procedureTs, obs.timestamp);
        const bucket = this.monthly.get(month);
        if (!bucket) continue;

        const idx = bucket.indexOf(obs.value);
        if (idx !== -1) bucket.splice(idx, 1);
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
  getStats(): Record<number, DistributionStats> {
    const result: Record<number, DistributionStats> = {};

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

  /** Serialises the current snapshot, ordered by relative month. */
  toCSV(): string {
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
  }

  // ================================
  // Helpers
  // ================================

  /** Calendar-month difference; day and time within a month are intentionally ignored. */
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
