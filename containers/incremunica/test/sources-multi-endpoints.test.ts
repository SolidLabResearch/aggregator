import { getSources } from '../main';
import { QuerySourceIterator } from '@incremunica/user-tools';

describe('getSources with multiple dynamic endpoints', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('deduplicates across endpoints and removes only when no endpoint lists the source', async () => {
    const ep1Events: string[] = [];
    const ep2Events: string[] = [];

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

      if (url === 'https://ep1/query') {
        return new Response(JSON.stringify({
          results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] }
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (url === 'https://ep2/query') {
        return new Response(JSON.stringify({
          results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] }
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      if (url === 'https://ep1/query/events') {
        ep1Events.push(
          'event: initial\ndata: {}\n\n',
          'event: update\ndata: {"deletions":[{"a":{"type":"uri","value":"https://ex.org/A"}}]}\n\n'
        );
        return new Response(createSSEStream(ep1Events), {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' }
        });
      }
      if (url === 'https://ep2/query/events') {
        ep2Events.push(
          'event: initial\ndata: {}\n\n',
          'event: update\ndata: {"deletions":[{"a":{"type":"uri","value":"https://ex.org/A"}}]}\n\n'
        );
        return new Response(createSSEStream(ep2Events), {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' }
        });
      }

      if (url.endsWith('/fetch')) {
        const body = JSON.parse((input as Request).body as any);
        if (body.url === 'https://ep1/query') {
          return new Response(JSON.stringify({
            results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] }
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (body.url === 'https://ep2/query') {
          return new Response(JSON.stringify({
            results: { bindings: [ { a: { type: 'uri', value: 'https://ex.org/A' } } ] }
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (body.url === 'https://ep1/query/events') {
          return new Response(createSSEStream(ep1Events), {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' }
          });
        }
        if (body.url === 'https://ep2/query/events') {
          return new Response(createSSEStream(ep2Events), {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' }
          });
        }
      }

      return new Response('Not found', { status: 404 });
    }) as any;

    const iterator: QuerySourceIterator = await getSources([
      { endpoint: 'https://ep1/query', variables: ['a'] },
      { endpoint: 'https://ep2/query', variables: ['a'] },
    ]);

    const initialDrain = await drain(iterator, 10);
    expect(initialDrain.additions.filter(s => s === 'https://ex.org/A').length).toBe(1);
    expect(initialDrain.deletions.length).toBe(0);

    await new Promise(resolve => setTimeout(resolve, 100));

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
