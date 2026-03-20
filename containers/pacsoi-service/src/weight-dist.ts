type WeightObservation = {
  value: number;
  timestamp: Date;
};

type PatientData = {
  procedureTs: Date;
  observations: WeightObservation[];
};

type MonthStats = {
  values: number[];
};

export class WeightDistribution {
  private patients = new Map<string, PatientData>();
  private monthly = new Map<number, MonthStats>();

  // ================================
  // Public API
  // ================================

  addPatientProcedure(patientID: string, timestamp: Date) {
    const existing = this.patients.get(patientID);

    if (existing && timestamp <= existing.procedureTs) {
      this.patients.set(patientID, {
        procedureTs: timestamp,
        observations: [],
      });
    }
  }

  addWeightObservation(patientID: string, value: number, timestamp: Date) {
    const patient = this.patients.get(patientID);
    if (!patient) return;

    if (timestamp < patient.procedureTs) return;

    const month = this.monthsSince(patient.procedureTs, timestamp);

    const obs = { value, timestamp };
    patient.observations.push(obs);

    if (!this.monthly.has(month)) {
      this.monthly.set(month, { values: [] });
    }

    this.monthly.get(month)!.values.push(value);
  }

  removePatient(patientID: string) {
    const patient = this.patients.get(patientID);
    if (!patient) return;

    // Remove their contributions from monthly stats
    for (const obs of patient.observations) {
      const month = this.monthsSince(patient.procedureTs, obs.timestamp);
      const bucket = this.monthly.get(month);
      if (!bucket) continue;

      const idx = bucket.values.indexOf(obs.value);
      if (idx !== -1) bucket.values.splice(idx, 1);
    }

    this.patients.delete(patientID);
  }

  // ================================
  // Stats
  // ================================

  getStats() {
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

    return result;
  }

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