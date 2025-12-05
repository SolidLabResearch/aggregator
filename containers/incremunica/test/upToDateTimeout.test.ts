import { UpToDateTimeout } from '../main';

describe('UpToDateTimeout', () => {
  it('fires only after last reset', () => {
    jest.useFakeTimers();
    const calls: number[] = [];
    const t = new UpToDateTimeout(50, () => calls.push(Date.now()));
    expect(t.isUpToDate()).toBe(false);

    t.reset();
    expect(t.isUpToDate()).toBe(false);

    // Reset several times within interval
    jest.advanceTimersByTime(25);
    t.reset();
    jest.advanceTimersByTime(25);
    t.reset();

    // No callback yet
    expect(calls.length).toBe(0);

    // Finally advance beyond interval
    jest.advanceTimersByTime(60);
    expect(calls.length).toBe(1);
    expect(t.isUpToDate()).toBe(true);

    jest.useRealTimers();
  });
});

