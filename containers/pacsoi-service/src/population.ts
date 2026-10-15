/**
 * Operational view of the active-patient population: how many patients the
 * last successful poll returned, and for each source group how many patients
 * are connected, still connecting, unauthorized, failed, or stopped because
 * their whole patient was suspended. Contains counts only, never identifiers.
 */

export const SOURCE_GROUPS = ["patient", "weight", "bariatric"] as const;
export type SourceGroup = (typeof SOURCE_GROUPS)[number];

export const GROUP_STATUSES = ["ok", "connecting", "unauthorized", "failed", "stopped"] as const;
export type GroupStatus = (typeof GROUP_STATUSES)[number];

export type GroupCounts = Record<GroupStatus, number>;

export interface PopulationSnapshot {
  activePatients: number;
  lastPoll: { at: string; ok: boolean; error?: string } | null;
  groups: Record<SourceGroup, GroupCounts>;
}

export class PopulationStatus {
  private activePatients = 0;
  private lastPoll: PopulationSnapshot["lastPoll"] = null;
  private readonly statuses = new Map<string, Record<SourceGroup, GroupStatus>>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  /** Records a successful poll and forgets patients that are no longer active. */
  pollSucceeded(activePatientIDs: Iterable<string>): void {
    const active = new Set(activePatientIDs);
    this.activePatients = active.size;
    for (const patientID of this.statuses.keys()) {
      if (!active.has(patientID)) this.statuses.delete(patientID);
    }
    this.lastPoll = { at: this.now().toISOString(), ok: true };
  }

  /** Records a failed poll; the previous population is retained. */
  pollFailed(error: string): void {
    this.lastPoll = { at: this.now().toISOString(), ok: false, error };
  }

  set(patientID: string, group: SourceGroup, status: GroupStatus): void {
    let groups = this.statuses.get(patientID);
    if (!groups) {
      groups = { patient: "connecting", weight: "connecting", bariatric: "connecting" };
      this.statuses.set(patientID, groups);
    }
    groups[group] = status;
  }

  get(patientID: string, group: SourceGroup): GroupStatus | undefined {
    return this.statuses.get(patientID)?.[group];
  }

  snapshot(): PopulationSnapshot {
    const groups = Object.fromEntries(
      SOURCE_GROUPS.map((group) => [
        group,
        Object.fromEntries(GROUP_STATUSES.map((status) => [status, 0])) as GroupCounts,
      ]),
    ) as Record<SourceGroup, GroupCounts>;
    for (const statuses of this.statuses.values()) {
      for (const group of SOURCE_GROUPS) groups[group][statuses[group]]++;
    }
    return {
      activePatients: this.activePatients,
      lastPoll: this.lastPoll && { ...this.lastPoll },
      groups,
    };
  }
}
