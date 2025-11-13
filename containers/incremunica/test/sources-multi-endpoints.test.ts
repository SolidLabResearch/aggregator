import { getSources } from '../main';
import { QuerySourceIterator } from '@incremunica/user-tools';

describe('getSources with multiple dynamic endpoints', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it('deduplicates across endpoints and removes only when no endpoint lists the source', async () => {
    jest.useFakeTimers();

    const responses: Record<string, any[]> = {
      'https://ep1/query': [
        { results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] } },
        { results: { bindings: [] } },
        { results: { bindings: [] } },
      ],
      'https://ep2/query': [
        { results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] } },
        { results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] } },
        { results: { bindings: [] } },
      ],
    };
    const fetchCounts: Record<string, number> = { 'https://ep1/query': 0, 'https://ep2/query': 0 };

    global.fetch = jest.fn(async (input: any) => {
      const url = typeof input === 'string' ? input : input.toString();
      const pick = (endpoint: string) => {
        const arr = responses[endpoint];
        const idx = fetchCounts[endpoint];
        const payload = idx < arr.length ? arr[idx] : arr[arr.length - 1];
        fetchCounts[endpoint]++;
        return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
      };
      if (url === 'https://ep1/query') return pick('https://ep1/query');
      if (url === 'https://ep2/query') return pick('https://ep2/query');
      if (url.endsWith('/fetch')) {
        const body = JSON.parse((input as Request).body as any);
        return pick(body.url);
      }
      return new Response('Not found', { status: 404 });
    }) as any;

    const iterator: QuerySourceIterator = await getSources([
      { endpoint: 'https://ep1/query', variables: ['a'] },
      { endpoint: 'https://ep2/query', variables: ['a'] },
    ], 50);

    const initialDrain = await drain(iterator, 10);
    expect(initialDrain.additions.filter(s => s === 'https://ex.org/A').length).toBe(1);
    expect(initialDrain.deletions.length).toBe(0);

    while (fetchCounts['https://ep2/query'] < 3) {
      await jest.advanceTimersByTimeAsync(50);
      await Promise.resolve(); // flush microtasks
    }

    const finalDrain = await drain(iterator, 20);
    const deletionCount = finalDrain.deletions.filter(s => s === 'https://ex.org/A').length;
    expect(deletionCount).toBe(1);
    expect(finalDrain.additions.filter(s => s === 'https://ex.org/A').length).toBe(0);

    iterator.close();
  });
});

async function drain(iter: QuerySourceIterator, limit = 100) {
  const additions: string[] = [];
  const deletions: string[] = [];
  let i = 0;
  while (iter.readable && i < limit) {
    const el = iter.read();
    if (!el) break;
    if (el.isAddition) additions.push(el.querySource as string);
    else deletions.push(el.querySource as string);
    i++;
  }
  return { additions, deletions };
}
