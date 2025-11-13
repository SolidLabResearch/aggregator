describe('customFetch proxy vs direct behavior', () => {
  const OLD_ENV = process.env;
  const originalFetch = global.fetch;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...OLD_ENV };
  });
  afterEach(() => {
    process.env = OLD_ENV;
    global.fetch = originalFetch;
  });

  it('falls back to direct fetch when proxy is not set', async () => {
    delete process.env.http_proxy;
    delete process.env.HTTP_PROXY;
    const mock = jest.fn(async () => new Response('ok', { status: 200 }));
    global.fetch = mock as any;

    const { customFetch } = await import('../main');
    await customFetch('https://example.test/data');

    expect(mock).toHaveBeenCalledTimes(1);
    const calls = (mock.mock.calls as unknown as any[][]);
    expect(calls.length).toBe(1);
    expect(String(calls[0][0])).toBe('https://example.test/data');
  });

  it('uses proxy POST /fetch when proxy is set and preserves original url', async () => {
    process.env.http_proxy = 'http://proxy.local';
    const calls: any[] = [];
    global.fetch = jest.fn(async (input: any, init?: any) => {
      calls.push({ input, init });
      // Always return OK with headers to trigger registration side-effect
      return new Response('ok', {
        status: 200,
        headers: new Headers({ 'X-Derivation-Issuer': 'issuer', 'X-Derivation-Resource-Id': 'rid' })
      });
    }) as any;

    const { customFetch } = await import('../main');
    const res = await customFetch('https://original.example/resource');

    expect((global.fetch as any).mock.calls[0][0]).toBe('http://proxy.local/fetch');
    const body = JSON.parse((global.fetch as any).mock.calls[0][1].body);
    expect(body.url).toBe('https://original.example/resource');
    expect(res.url).toBe('https://original.example/resource');
  });
});

