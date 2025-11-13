import type http from 'http';
import { SSEConnectionManager } from '../main';

describe('SSEConnectionManager', () => {
  jest.useFakeTimers();

  function createStubResponse() {
    const writes: string[] = [];
    let closeHandler: (() => void) | undefined;
    const res: Partial<http.ServerResponse> & { writes: string[]; triggerClose: () => void } = {
      writes,
      write: (chunk: any) => { writes.push(String(chunk)); return true; },
      on: (event: string, handler: any) => { if (event === 'close') closeHandler = handler; return res as any; },
      triggerClose: () => { closeHandler && closeHandler(); },
    } as any;
    return res;
  }

  it('sends heartbeat and clears on close', () => {
    const mgr = new SSEConnectionManager();
    const res = createStubResponse();

    mgr.addConnection(res as any);

    jest.advanceTimersByTime(30000);
    expect(res.writes.join('')).toContain('event: heartbeat');

    res.triggerClose();
    const countBefore = res.writes.length;
    jest.advanceTimersByTime(60000);
    // no new heartbeats after close
    expect(res.writes.length).toBe(countBefore);
  });

  it('broadcast sends to all connections', () => {
    const mgr = new SSEConnectionManager();
    const a = createStubResponse();
    const b = createStubResponse();

    mgr.addConnection(a as any);
    mgr.addConnection(b as any);

    mgr.broadcast('addition', { foo: 'bar' });

    expect(a.writes.join('')).toContain('event: addition');
    expect(a.writes.join('')).toContain('"foo":"bar"');
    expect(b.writes.join('')).toContain('event: addition');
  });
});

