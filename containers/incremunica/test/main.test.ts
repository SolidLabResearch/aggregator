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

describe('getSources with SSE streams', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('seeds static sources and performs additions/removals from dynamic endpoint via SSE', async () => {
    const sseEvents: string[] = [];

    function createSSEStream(events: string[]) {
      let eventIndex = 0;
      const encoder = new TextEncoder();

      return new ReadableStream({
        pull(controller) {
          if (eventIndex < events.length) {
            controller.enqueue(encoder.encode(events[eventIndex]));
            eventIndex++;
          }
        }
      });
    }

    global.fetch = jest.fn(async (input: any) => {
      const url = typeof input === 'string' ? input : input.toString();

      if (url === 'https://dynamic.endpoint/query') {
        return new Response(JSON.stringify({
          results: {
            bindings: [
              { a: { type: 'uri', value: 'https://ex.org/1' } },
              { a: { type: 'uri', value: 'https://ex.org/2' } }
            ]
          }
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      if (url === 'https://dynamic.endpoint/query/events') {
        sseEvents.push(
          'event: initial\ndata: {}\n\n',
          'event: update\ndata: {"deletions":[{"a":{"type":"uri","value":"https://ex.org/2"}}]}\n\n',
          'event: update\ndata: {"additions":[{"a":{"type":"uri","value":"https://ex.org/3"}}]}\n\n'
        );
        return new Response(createSSEStream(sseEvents), {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' }
        });
      }

      if (url.endsWith('/fetch')) {
        const body = JSON.parse((input as Request).body as any);
        if (body.url === 'https://dynamic.endpoint/query') {
          return new Response(JSON.stringify({
            results: {
              bindings: [
                { a: { type: 'uri', value: 'https://ex.org/1' } },
                { a: { type: 'uri', value: 'https://ex.org/2' } }
              ]
            }
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (body.url === 'https://dynamic.endpoint/query/events') {
          return new Response(createSSEStream(sseEvents), {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' }
          });
        }
      }

      return new Response('Not found', { status: 404 });
    }) as any;

    const staticTerm = { termType: 'NamedNode', value: 'https://static.org' };
    const dynamicDescriptor = { endpoint: 'https://dynamic.endpoint/query', variables: ['a'] };

    const iterator = await getSources([ staticTerm, dynamicDescriptor ]);

    let drained = await drainIterator(iterator, 10);
    expect(drained.additions).toEqual(expect.arrayContaining(['https://static.org', 'https://ex.org/1', 'https://ex.org/2']));

    await new Promise(resolve => setTimeout(resolve, 100));

    drained = await drainIterator(iterator, 10);
    expect(drained.additions).toEqual(expect.arrayContaining(['https://ex.org/3']));
    expect(drained.deletions).toEqual(expect.arrayContaining(['https://ex.org/2']));

    iterator.close();
  });
});
