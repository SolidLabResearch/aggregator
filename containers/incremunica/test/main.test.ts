import { getSourceValue, collectSourcesFromBindingObject, getSources } from '../main';
import { QuerySourceIterator } from '@incremunica/user-tools';

// Minimal helper to exhaust iterator
async function drainIterator(iter: QuerySourceIterator, limit = 100): Promise<{ additions: string[]; deletions: string[] }> {
  const additions: string[] = [];
  const deletions: string[] = [];
  let count = 0;
  while (iter.readable && count < limit) {
    const element = iter.read();
    if (!element) break;
    if (element.isAddition) additions.push(element.querySource as string);
    else deletions.push(element.querySource as string);
    count++;
  }
  return { additions, deletions };
}

describe('getSourceValue', () => {
  it('extracts value from NamedNode-like term', () => {
    expect(getSourceValue({ termType: 'NamedNode', value: 'https://example.org' })).toBe('https://example.org');
  });
  it('extracts value from Literal-like term', () => {
    expect(getSourceValue({ termType: 'Literal', value: 'https://example.org/data' })).toBe('https://example.org/data');
  });
  it('returns undefined for other term types', () => {
    expect(getSourceValue({ termType: 'BlankNode', value: '_:b1' })).toBeUndefined();
    expect(getSourceValue(undefined)).toBeUndefined();
  });
});

describe('collectSourcesFromBindingObject', () => {
  it('collects URIs from specified variables', () => {
    const binding = {
      s: { type: 'uri', value: 'https://ex.org/s' },
      p: { type: 'uri', value: 'https://ex.org/p' },
      o: { type: 'literal', value: 'Literal' },
    };
    expect(collectSourcesFromBindingObject(binding, ['?s', '?p'])).toEqual([
      'https://ex.org/s',
      'https://ex.org/p',
    ]);
  });
  it('falls back to all keys when variables empty', () => {
    const binding = {
      a: { type: 'uri', value: 'https://ex.org/a' },
      b: { type: 'uri', value: 'https://ex.org/b' },
      c: { type: 'literal', value: 'not a uri' },
    };
    const result = collectSourcesFromBindingObject(binding, []);
    expect(result).toEqual(['https://ex.org/a', 'https://ex.org/b']);
  });
  it('ignores non-object and non-uri entries', () => {
    const binding: any = {
      x: { type: 'literal', value: 'text' },
      y: { type: 'bnode', value: '_:b' },
      z: { type: 'uri', value: '' },
    };
    expect(collectSourcesFromBindingObject(binding, ['x', 'y', 'z'])).toEqual([]);
  });
});

describe('getSources dynamic polling', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it('seeds static sources and performs additions/removals from dynamic endpoint', async () => {
    jest.useFakeTimers();

    const responses: Record<string, any[]> = {
      'https://dynamic.endpoint/query': [
        // First poll returns two sources
        { results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/1' } }, { a: { type: 'uri', value: 'https://ex.org/2' } } ] } },
        // Second poll removes 2, adds 3
        { results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/1' } }, { a: { type: 'uri', value: 'https://ex.org/3' } } ] } },
      ],
    };
    const fetchCallCount: Record<string, number> = { 'https://dynamic.endpoint/query': 0 };

    global.fetch = jest.fn(async (input: any) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.startsWith('http://') || url.startsWith('https://')) {
        const arr = responses['https://dynamic.endpoint/query'];
        const idx = fetchCallCount['https://dynamic.endpoint/query'];
        const payload = idx < arr.length ? arr[idx] : arr[arr.length - 1];
        fetchCallCount['https://dynamic.endpoint/query']++;
        return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      // Proxy fetch endpoint expectation in customFetch
      if (url.endsWith('/fetch')) {
        // Extract original URL from body
        const body = JSON.parse((input as Request).body as any);
        const arr = responses['https://dynamic.endpoint/query'];
        const idx = fetchCallCount['https://dynamic.endpoint/query'];
        const payload = idx < arr.length ? arr[idx] : arr[arr.length - 1];
        fetchCallCount['https://dynamic.endpoint/query']++;
        return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response('Not found', { status: 404 });
    }) as any;

    const staticTerm = { termType: 'NamedNode', value: 'https://static.org' };
    const dynamicDescriptor = { endpoint: 'https://dynamic.endpoint/query', variables: ['a'] };

    const iterator = await getSources([ staticTerm, dynamicDescriptor ], 50); // fast poll

    // Drain initial state (static + first dynamic poll)
    let drained = await drainIterator(iterator, 10);
    expect(drained.additions).toEqual(expect.arrayContaining(['https://static.org', 'https://ex.org/1', 'https://ex.org/2']));

    // Advance timers for next poll
    await jest.advanceTimersByTimeAsync(60);
    drained = await drainIterator(iterator, 10);
    // We expect a removal of https://ex.org/2 and addition of https://ex.org/3
    expect(drained.additions).toEqual(expect.arrayContaining(['https://ex.org/3']));
    expect(drained.deletions).toEqual(expect.arrayContaining(['https://ex.org/2']));

    iterator.close();
  });
});
