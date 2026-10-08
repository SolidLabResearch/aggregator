/**
 * The question identifiers emitted by the combined bariatric questionnaires.
 *
 * The first OWLQOL item has no numeric suffix in the source data and item 7 is
 * consequently absent. Keep these identifiers explicit so a questionnaire
 * definition change cannot silently produce a plausible, but invalid, score.
 */
export const OWLQOL_QUESTIONS = new Set([
  "OWLQOL",
  "OWLQOL1",
  "OWLQOL2",
  "OWLQOL3",
  "OWLQOL4",
  "OWLQOL5",
  "OWLQOL6",
  "OWLQOL8",
  "OWLQOL9",
  "OWLQOL10",
  "OWLQOL11",
  "OWLQOL12",
  "OWLQOL13",
  "OWLQOL14",
  "OWLQOL15",
  "OWLQOL16",
  "OWLQOL17",
]);

const WRSM_ITEM_COUNT = 20;

export interface BariatricQuestionnaireScores {
  /** OWLQOL score on a 0-100 scale. Higher is better. */
  owlqol: number;
  /** Sum of WRSM symptom bother ratings, on a 0-120 scale. Lower is better. */
  wrsmBother: number;
}

/**
 * Collects the OWLQOL and WRSM answers from one combined questionnaire.
 * Unrelated answers (currently BAROS) are deliberately ignored.
 */
export class BariatricScoreBuffer {
  private readonly owlqolAnswers = new Map<string, number>();
  private readonly wrsmPresenceAnswers = new Map<number, number>();
  private readonly wrsmBotherAnswers = new Map<number, number>();

  constructor(public readonly id: string) {}

  /**
   * Adds an answer. Returns false when the question does not belong to OWLQOL
   * or WRSM, allowing a caller to pass every answer from the combined form.
   */
  addAnswer(question: string, rawValue: string): boolean {
    const code = question.split("/").pop() ?? question;

    if (OWLQOL_QUESTIONS.has(code)) {
      const value = this.parseIntegerInRange(code, rawValue, 0, 6);
      this.addUnique(this.owlqolAnswers, code, value);
      return true;
    }

    const wrsmMatch = /^WRSM(\d{1,2})([ab])?$/.exec(code);
    if (!wrsmMatch) {
      if (code.startsWith("OWLQOL") || code.startsWith("WRSM")) {
        throw new Error(`Unexpected bariatric question: ${question}`);
      }
      return false;
    }

    const item = Number(wrsmMatch[1]);
    if (item < 1 || item > WRSM_ITEM_COUNT) {
      throw new Error(`Unexpected WRSM item: ${question}`);
    }

    const suffix = wrsmMatch[2];
    if (!suffix) {
      const value = this.parseIntegerInRange(code, rawValue, 0, 1);
      this.addUnique(this.wrsmPresenceAnswers, item, value);
    } else {
      this.validateBotherSuffix(item, suffix, question);
      const value = this.parseIntegerInRange(code, rawValue, 0, 6);
      this.addUnique(this.wrsmBotherAnswers, item, value);
    }

    return true;
  }

  /** Removes one previously observed answer. Returns false for unrelated questions. */
  removeAnswer(question: string, rawValue: string): boolean {
    const code = question.split("/").pop() ?? question;

    if (OWLQOL_QUESTIONS.has(code)) {
      const value = this.parseIntegerInRange(code, rawValue, 0, 6);
      return this.removeExact(this.owlqolAnswers, code, value);
    }

    const wrsmMatch = /^WRSM(\d{1,2})([ab])?$/.exec(code);
    if (!wrsmMatch) {
      if (code.startsWith("OWLQOL") || code.startsWith("WRSM")) {
        throw new Error(`Unexpected bariatric question: ${question}`);
      }
      return false;
    }

    const item = Number(wrsmMatch[1]);
    if (item < 1 || item > WRSM_ITEM_COUNT) {
      throw new Error(`Unexpected WRSM item: ${question}`);
    }

    const suffix = wrsmMatch[2];
    const isBother = suffix !== undefined;
    if (suffix) this.validateBotherSuffix(item, suffix, question);
    const value = this.parseIntegerInRange(code, rawValue, 0, isBother ? 6 : 1);
    return isBother
      ? this.removeExact(this.wrsmBotherAnswers, item, value)
      : this.removeExact(this.wrsmPresenceAnswers, item, value);
  }

  /** True when all answers needed for both scores have arrived. */
  complete(): boolean {
    if (
      this.owlqolAnswers.size !== OWLQOL_QUESTIONS.size ||
      this.wrsmPresenceAnswers.size !== WRSM_ITEM_COUNT
    ) {
      return false;
    }

    for (const [item, present] of this.wrsmPresenceAnswers) {
      if (present === 1 && !this.wrsmBotherAnswers.has(item)) return false;
    }

    return true;
  }

  /** Merges partial bindings for the same response after identity resolution. */
  merge(other: BariatricScoreBuffer): void {
    if (other.id !== this.id) {
      throw new Error(`Cannot merge response ${other.id} into ${this.id}`);
    }

    this.mergeAnswers(this.owlqolAnswers, other.owlqolAnswers);
    this.mergeAnswers(this.wrsmPresenceAnswers, other.wrsmPresenceAnswers);
    this.mergeAnswers(this.wrsmBotherAnswers, other.wrsmBotherAnswers);
  }

  /** Calculates the OWLQOL and total WRSM bother scores. */
  getScores(): BariatricQuestionnaireScores {
    if (!this.complete()) {
      throw new Error(`Bariatric response ${this.id} is incomplete`);
    }

    let owlqolRaw = 0;
    for (const value of this.owlqolAnswers.values()) owlqolRaw += value;

    let wrsmBother = 0;
    for (let item = 1; item <= WRSM_ITEM_COUNT; item++) {
      const present = this.wrsmPresenceAnswers.get(item)!;
      const bother = this.wrsmBotherAnswers.get(item);

      if (present === 0 && bother !== undefined && bother !== 0) {
        throw new Error(
          `WRSM item ${item} is absent but has a non-zero bother rating`,
        );
      }

      // The form omits the "b" answer when a symptom is absent. Such an item
      // contributes zero to the bothersomeness score.
      if (present === 1) wrsmBother += bother!;
    }

    // All 17 OWLQOL items are negatively phrased and scored 0-6. Reverse the
    // raw responses, then transform the 0-102 total to the documented 0-100.
    const owlqolMaximum = OWLQOL_QUESTIONS.size * 6;
    const owlqol = ((owlqolMaximum - owlqolRaw) / owlqolMaximum) * 100;

    return { owlqol, wrsmBother };
  }

  private addUnique<K>(answers: Map<K, number>, key: K, value: number): void {
    if (answers.has(key)) {
      throw new Error(`Response ${this.id} already has answer for ${String(key)}`);
    }
    answers.set(key, value);
  }

  private removeExact<K>(answers: Map<K, number>, key: K, value: number): boolean {
    const existing = answers.get(key);
    if (existing === undefined) return false;
    if (existing !== value) {
      throw new Error(
        `Cannot remove answer ${String(key)}=${value} from response ${this.id}; stored value is ${existing}`,
      );
    }
    answers.delete(key);
    return true;
  }

  private validateBotherSuffix(item: number, suffix: string, question: string): void {
    const expected = item <= 2 ? "a" : "b";
    if (suffix !== expected) {
      throw new Error(
        `Unexpected WRSM bother question: ${question}; expected WRSM${item}${expected}`,
      );
    }
  }

  private mergeAnswers<K>(target: Map<K, number>, source: Map<K, number>): void {
    for (const [key, value] of source) {
      const existing = target.get(key);
      if (existing !== undefined && existing !== value) {
        throw new Error(
          `Cannot merge response ${this.id}: conflicting answer for ${String(key)}`,
        );
      }
      target.set(key, value);
    }
  }

  private parseIntegerInRange(
    question: string,
    rawValue: string,
    minimum: number,
    maximum: number,
  ): number {
    const value = Number(rawValue);
    if (!Number.isInteger(value) || value < minimum || value > maximum) {
      throw new Error(
        `Invalid value ${JSON.stringify(rawValue)} for ${question}; ` +
          `expected an integer from ${minimum} to ${maximum}`,
      );
    }
    return value;
  }
}
