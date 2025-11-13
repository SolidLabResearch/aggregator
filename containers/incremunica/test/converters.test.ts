import { materializedViewToSparqlJson, bindingToSparqlJson } from '../main';

describe('SPARQL JSON converters', () => {
  it('materializedViewToSparqlJson builds head and results with counts', () => {
    const mkVar = (name: string) => ({ value: name });
    const named = (iri: string) => ({ termType: 'NamedNode', value: iri });
    const literal = (v: string, dt?: string, lang?: string) => ({ termType: 'Literal', value: v, datatype: dt ? { value: dt } : undefined, language: lang });

    const m = new Map<string, { bindings: any, count: number }>();
    // First binding appears twice
    const b1 = new Map<any, any>([
      [mkVar('s'), named('https://ex.org/s')],
      [mkVar('o'), literal('42', 'http://www.w3.org/2001/XMLSchema#integer')],
    ]);
    m.set('b1', { bindings: b1, count: 2 });

    const b2 = new Map<any, any>([
      [mkVar('s'), named('https://ex.org/s2')],
      [mkVar('label'), literal('hello', undefined, 'en')],
    ]);
    m.set('b2', { bindings: b2, count: 1 });

    const out = materializedViewToSparqlJson(m);
    expect(out.head.vars.sort()).toEqual(['label','o','s'].sort());
    expect(out.results.bindings.length).toBe(3);
    const labels = out.results.bindings.map((r: any) => r.label?.value).filter(Boolean);
    expect(labels).toEqual(['hello']);
  });

  it('bindingToSparqlJson wraps a single binding in array', () => {
    const mkVar = (name: string) => ({ value: name });
    const named = (iri: string) => ({ termType: 'NamedNode', value: iri });

    const b = new Map<any, any>([[mkVar('s'), named('https://ex.org/s')]]);
    const out = bindingToSparqlJson(b);
    expect(Array.isArray(out.bindings)).toBe(true);
    expect(out.bindings[0].s.value).toBe('https://ex.org/s');
  });
});

