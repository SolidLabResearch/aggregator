type WeightObservation = {
  id: string;
  value: number;
  timestamp: Date;
};

type PatientProcedure = {
  id: string;
  timestamp: Date;
};

type PatientData = {
  patientIDs: Set<string>;
  identifiers: Set<string>;
  procedures: PatientProcedure[];
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
  private nextRecordID = 1;
  private identifiers = new Map<string, string>();
  private issuedIdentifiers = new Map<string, string>();
  private patients = new Map<string, PatientData>();
  private monthly = new Map<number, number[]>();
  private procedureBuffer = new Map<string, PatientProcedure[]>();
  private observationsBuffer = new Map<string, WeightObservation[]>();

  // ================================
  // Public API
  // ================================
  /** Registers the canonical patient URI and, optionally, a pseudo identifier. */
  addPatientIdentifier(patientID: string, identifier?: string, issuer?: string) {
    let recordID = this.identifiers.get(patientID);
    if (!recordID) {
      recordID = `record-${this.nextRecordID++}`;
      console.log(`[addPatientIdentifier] Adding ${patientID} to new record ${recordID}`);
      this.patients.set(recordID, {
        patientIDs: new Set([patientID]),
        identifiers: new Set([patientID]),
        procedures: [],
        observations: []
      });
      this.identifiers.set(patientID, recordID);
    }

    if (identifier) {
      if (!issuer) {
        console.warn(`[addPatientIdentifier] Ignoring identifier ${identifier} without issuer`);
      } else {
        const identityKey = JSON.stringify([issuer, identifier]);
        const matchingRecordID = this.issuedIdentifiers.get(identityKey);
        if (matchingRecordID && matchingRecordID !== recordID) {
          recordID = this.mergeRecords(recordID, matchingRecordID);
        }
        const record = this.patients.get(recordID)!;
        record.patientIDs.add(patientID);
        record.identifiers.add(identifier);
        this.identifiers.set(patientID, recordID);
        this.identifiers.set(identifier, recordID);
        this.issuedIdentifiers.set(identityKey, recordID);
        console.log(`[addPatientIdentifier] Added ${issuer}|${identifier} to ${recordID}`);
      }
    }

    this.flushProcedures(recordID);
    this.flushObservations(recordID);
  }

  /** Records a procedure and re-buckets observations when the earliest one changes. */
  addPatientProcedure(identifier: string, procedureID: string, timestamp: Date) {
    console.log(`[addPatientProcedure] Recieved procedure for ID ${identifier} at ${timestamp.toISOString()}`);
    const recordID = this.identifiers.get(identifier);
    if (!recordID) {
      const buffer = this.procedureBuffer.get(identifier) ?? [];
      // Re-added sources replay their data; procedures are unique by ID.
      if (buffer.some(procedure => procedure.id === procedureID)) return;
      console.log(`[addPatientProcedure] No data yet for ID ${identifier}. Buffering procedure at ${timestamp.toISOString()}`);
      buffer.push({ id: procedureID, timestamp });
      this.procedureBuffer.set(identifier, buffer);
      return;
    }

    const data = this.patients.get(recordID);
    if (!data) {
      console.warn(`[addPatientProcedure] Patient ${recordID} has identifiers but no data. Skipping...`);
      return;
    }
    if (data.procedures.some(procedure => procedure.id === procedureID)) return;

    this.replaceProcedureState(data, () => data.procedures.push({ id: procedureID, timestamp }));
    console.log(`[addPatientProcedure] Added procedure ${procedureID} for patient ${recordID}`);
    this.flushObservations(recordID);
  }

  /** Adds a weight to its calendar-month bucket, buffering if prerequisites are missing. */
  addWeightObservation(identifier: string, observationID: string, value: number, timestamp: Date) {
    const observation = { id: observationID, value, timestamp };

    const bufferObservation = (reason: string) => {
      console.log(
        `[addWeightObservation] ${reason}. Buffering observation ${value} at ${timestamp.toISOString()}`
      );

      if (!this.observationsBuffer.has(identifier)) {
        this.observationsBuffer.set(identifier, []);
      }

      const buffer = this.observationsBuffer.get(identifier)!;
      if (!buffer.some(buffered => buffered.id === observationID)) buffer.push(observation);
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

    // Re-added sources replay their data; observations are unique by ID.
    if (data.observations.some(existing => existing.id === observationID)) return;
    data.observations.push(observation);
    const procedure = this.effectiveProcedure(data);
    if (!procedure) {
      console.log(`[addWeightObservation] No procedure yet for patient ${patientID}; retaining observation`);
      return;
    }

    this.addObservationContribution(procedure.timestamp, observation);
    const month = this.monthsSince(procedure.timestamp, timestamp);

    console.log(
      `[addWeightObservation] Added observation ${value} at ${timestamp.toISOString()} ` +
        `for patient ${patientID}, month ${month}`
    );
  }

  removeWeightObservation(identifier: string, observationID: string): void {
    const recordID = this.identifiers.get(identifier) ?? this.findRecordByObservation(observationID);
    if (!recordID) {
      const buffer = this.observationsBuffer.get(identifier);
      if (!buffer) return;
      const index = buffer.findIndex(observation => observation.id === observationID);
      if (index !== -1) buffer.splice(index, 1);
      if (buffer.length === 0) this.observationsBuffer.delete(identifier);
      return;
    }

    const data = this.patients.get(recordID);
    if (!data) return;
    const index = data.observations.findIndex(observation => observation.id === observationID);
    if (index === -1) return;
    const [observation] = data.observations.splice(index, 1);
    const procedure = this.effectiveProcedure(data);
    if (procedure) this.removeObservationContribution(procedure.timestamp, observation);
  }

  removePatientProcedure(identifier: string, procedureID: string): void {
    const recordID = this.identifiers.get(identifier) ?? this.findRecordByProcedure(procedureID);
    if (!recordID) {
      const buffer = this.procedureBuffer.get(identifier);
      if (!buffer) return;
      const index = buffer.findIndex(procedure => procedure.id === procedureID);
      if (index !== -1) buffer.splice(index, 1);
      if (buffer.length === 0) this.procedureBuffer.delete(identifier);
      return;
    }

    const data = this.patients.get(recordID);
    if (!data) return;
    this.replaceProcedureState(data, () => {
      const index = data.procedures.findIndex(procedure => procedure.id === procedureID);
      if (index !== -1) data.procedures.splice(index, 1);
    });
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

  flushProcedures(patientID: string) {
    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[flushProcedures] Patient ${patientID} has no data. Skipping...`);
      return;
    }

    if (this.effectiveProcedure(data)) {
      console.log(`[flushProcedures] Patient ${patientID} already has a procedure. Skipping...`);
    }

    const buffered: PatientProcedure[] = [];
    for (const identifier of data.identifiers) {
      const buffer = this.procedureBuffer.get(identifier);
      if (buffer) {
        buffered.push(...buffer);
        this.procedureBuffer.delete(identifier);
      }
    }
    if (buffered.length > 0) {
      this.replaceProcedureState(data, () => data.procedures.push(...buffered));
      this.flushObservations(patientID);
    }
  }

  flushObservations(patientID: string) {
    const data = this.patients.get(patientID);
    if (!data) {
      console.warn(`[flushObservations] Patient ${patientID} has no data. Skipping...`);
      return
    }
    if (!this.effectiveProcedure(data)) {
      console.log(`[flushObservations] Patient ${patientID} has no procedure yet. Skipping...`);
      return;
    }

    for (const identifier of data.identifiers) {
      const buffer = this.observationsBuffer.get(identifier);
      if (buffer) {
        for (const obs of buffer) {
          this.addWeightObservation(identifier, obs.id, obs.value, obs.timestamp);
        }
        this.observationsBuffer.delete(identifier);
      }
    }
  }

  /**
   * Drops a patient's procedures and weights, including buffered ones, but
   * keeps the patient's identity. Used when the weight sources are suspended;
   * re-added sources replay the data from scratch.
   */
  clearPatientData(patientID: string): void {
    const recordID = this.identifiers.get(patientID);
    const patient = recordID ? this.patients.get(recordID) : undefined;
    if (!patient) return;
    this.removeWeightContributions(patient);
    patient.procedures = [];
    patient.observations = [];
    for (const identifier of patient.identifiers) {
      this.procedureBuffer.delete(identifier);
      this.observationsBuffer.delete(identifier);
    }
    console.log(`[clearPatientData] Cleared weight data of ${recordID}`);
  }

  /** Removes a patient and that patient's contribution from every aggregate. */
  removePatient(patientID: string) {
    console.log(`[removePatient] Removing patient ${patientID}`);
    const recordID = this.identifiers.get(patientID);
    const patient = recordID ? this.patients.get(recordID) : undefined;
    if (!patient) {
      console.log(`[removePatient] Patient ${patientID} not found`);
      return;
    }

    patient.patientIDs.delete(patientID);
    patient.identifiers.delete(patientID);
    this.identifiers.delete(patientID);
    if (patient.patientIDs.size > 0) {
      console.log(`[removePatient] Removed ${patientID} from ${recordID}; record retained`);
      return;
    }

    // Remove buffers
    for (const identifier of patient.identifiers) {
      this.procedureBuffer.delete(identifier);
      this.observationsBuffer.delete(identifier);
      this.identifiers.delete(identifier);
    }
    for (const [key, owner] of this.issuedIdentifiers) {
      if (owner === recordID) this.issuedIdentifiers.delete(key);
    }

    this.removeWeightContributions(patient);

    // This must also happen when no procedure was seen; otherwise re-adding the
    // patient leaves a stale record without an identifier mapping.
    this.patients.delete(recordID!);
    console.log(`[removePatient] Patient ${patientID} removed`);
  }

  // ================================
  // Stats
  // ================================

  /** Number of distinct patients contributing at least one weight to the distribution. */
  patientCount(): number {
    let count = 0;
    for (const patient of this.patients.values()) {
      if (patient.observations.length > 0 && this.effectiveProcedure(patient)) count++;
    }
    return count;
  }

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

  private mergeRecords(firstID: string, secondID: string): string {
    const first = this.patients.get(firstID)!;
    const second = this.patients.get(secondID)!;
    const recordID = `record-${this.nextRecordID++}`;
    this.removeWeightContributions(first);
    this.removeWeightContributions(second);
    const merged: PatientData = {
      patientIDs: new Set([...first.patientIDs, ...second.patientIDs]),
      identifiers: new Set([...first.identifiers, ...second.identifiers]),
      procedures: [...first.procedures, ...second.procedures],
      observations: [...first.observations, ...second.observations],
    };
    this.patients.delete(firstID);
    this.patients.delete(secondID);
    this.patients.set(recordID, merged);
    for (const alias of merged.identifiers) this.identifiers.set(alias, recordID);
    for (const [key, owner] of this.issuedIdentifiers) {
      if (owner === firstID || owner === secondID) this.issuedIdentifiers.set(key, recordID);
    }
    this.addWeightContributions(merged);
    console.log(`[mergeRecords] Merged ${firstID} and ${secondID} into ${recordID}`);
    return recordID;
  }

  private removeWeightContributions(patient: PatientData) {
    const procedure = this.effectiveProcedure(patient);
    if (!procedure) return;
    for (const obs of patient.observations) {
      this.removeObservationContribution(procedure.timestamp, obs);
    }
  }

  private addWeightContributions(patient: PatientData): void {
    const procedure = this.effectiveProcedure(patient);
    if (!procedure) return;
    for (const observation of patient.observations) {
      this.addObservationContribution(procedure.timestamp, observation);
    }
  }

  private findRecordByObservation(observationID: string): string | undefined {
    for (const [recordID, patient] of this.patients) {
      if (patient.observations.some(observation => observation.id === observationID)) return recordID;
    }
    return undefined;
  }

  private findRecordByProcedure(procedureID: string): string | undefined {
    for (const [recordID, patient] of this.patients) {
      if (patient.procedures.some(procedure => procedure.id === procedureID)) return recordID;
    }
    return undefined;
  }

  private effectiveProcedure(patient: PatientData): PatientProcedure | undefined {
    return patient.procedures.reduce<PatientProcedure | undefined>(
      (earliest, procedure) => !earliest || procedure.timestamp < earliest.timestamp ? procedure : earliest,
      undefined,
    );
  }

  private replaceProcedureState(patient: PatientData, change: () => void): void {
    this.removeWeightContributions(patient);
    change();
    this.addWeightContributions(patient);
  }

  private addObservationContribution(procedure: Date, observation: WeightObservation): void {
    const month = this.monthsSince(procedure, observation.timestamp);
    const bucket = this.monthly.get(month) ?? [];
    bucket.push(observation.value);
    this.monthly.set(month, bucket);
  }

  private removeObservationContribution(procedure: Date, observation: WeightObservation): void {
    const month = this.monthsSince(procedure, observation.timestamp);
    const bucket = this.monthly.get(month);
    if (!bucket) return;
    const index = bucket.indexOf(observation.value);
    if (index !== -1) bucket.splice(index, 1);
    if (bucket.length === 0) this.monthly.delete(month);
  }

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
