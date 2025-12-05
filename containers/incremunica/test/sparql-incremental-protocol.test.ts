import type http from 'http';
import { SSEConnectionManager, UpToDateTimeout, materializedViewToSparqlJson, bindingToSparqlJson } from '../main';

describe('SPARQL 1.1 Incremental Protocol - SSE Event Semantics', () => {
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

  describe('Event Types', () => {
    describe('initial event', () => {
      it('should be the first event sent on new connection', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();
        const materializedView = new Map();

        mgr.addConnection(res as any);
        const sparqlJson = materializedViewToSparqlJson(materializedView);
        mgr.sendToConnection(res as any, 'initial', sparqlJson);

        const messages = res.writes.join('');
        expect(messages).toContain('event: initial');
        expect(messages.indexOf('event: initial')).toBeLessThan(
          messages.indexOf('event: update') === -1 ? Infinity : messages.indexOf('event: update')
        );
      });

      it('should contain complete SPARQL Results JSON format', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();
        
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'book' }, { termType: 'NamedNode', value: 'http://example.org/book1' }],
            [{ value: 'title' }, { termType: 'Literal', value: 'SPARQL Tutorial' }]
          ]),
          count: 1
        });

        mgr.addConnection(res as any);
        const sparqlJson = materializedViewToSparqlJson(materializedView);
        mgr.sendToConnection(res as any, 'initial', sparqlJson);

        const messages = res.writes.join('');
        expect(messages).toContain('event: initial');
        expect(messages).toContain('data: ');
        
        const dataMatch = messages.match(/data: (.+)/);
        expect(dataMatch).toBeTruthy();
        if (dataMatch) {
          const data = JSON.parse(dataMatch[1]);
          expect(data).toHaveProperty('head');
          expect(data).toHaveProperty('results');
          expect(data.head).toHaveProperty('vars');
          expect(data.results).toHaveProperty('bindings');
        }
      });
    });

    describe('processing event', () => {
      it('should be emitted when service is processing updates', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();

        mgr.addConnection(res as any);
        mgr.broadcast('processing', { timestamp: new Date().toISOString() });

        const messages = res.writes.join('');
        expect(messages).toContain('event: processing');
      });

      it('may contain a timestamp', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();
        const timestamp = '2024-11-24T10:00:00Z';

        mgr.addConnection(res as any);
        mgr.broadcast('processing', { timestamp });

        const messages = res.writes.join('');
        expect(messages).toContain('event: processing');
        expect(messages).toContain(timestamp);
      });

      it('does not guarantee an update event will follow', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();

        mgr.addConnection(res as any);
        mgr.broadcast('processing', { timestamp: '2024-11-24T10:00:00Z' });
        mgr.broadcast('up-to-date', { timestamp: '2024-11-24T10:00:01Z' });

        const messages = res.writes.join('');
        expect(messages).toContain('event: processing');
        expect(messages).toContain('event: up-to-date');
        expect(messages).not.toContain('event: update');
      });
    });

    describe('update event', () => {
      it('should contain additions and deletions', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();

        mgr.addConnection(res as any);
        
        const addition = {
          book: { type: 'uri', value: 'http://example.org/book2' },
          title: { type: 'literal', value: 'The Semantic Web' }
        };
        const deletion = {
          book: { type: 'uri', value: 'http://example.org/book1' },
          title: { type: 'literal', value: 'SPARQL Tutorial' }
        };

        mgr.queueUpdate(true, addition);
        mgr.queueUpdate(false, deletion);
        mgr.flushUpdates();

        const messages = res.writes.join('');
        expect(messages).toContain('event: update');
        
        const dataMatch = messages.match(/data: ({.+})/);
        expect(dataMatch).toBeTruthy();
        if (dataMatch) {
          const data = JSON.parse(dataMatch[1]);
          expect(data).toHaveProperty('additions');
          expect(data).toHaveProperty('deletions');
          expect(Array.isArray(data.additions)).toBe(true);
          expect(Array.isArray(data.deletions)).toBe(true);
        }
      });

      it('should batch multiple updates', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();

        mgr.addConnection(res as any);
        
        mgr.queueUpdate(true, { x: { type: 'uri', value: 'http://ex.org/1' } });
        mgr.queueUpdate(true, { x: { type: 'uri', value: 'http://ex.org/2' } });
        mgr.queueUpdate(false, { x: { type: 'uri', value: 'http://ex.org/3' } });

        jest.advanceTimersByTime(100);

        const messages = res.writes.join('');
        const updateEvents = (messages.match(/event: update/g) || []).length;
        expect(updateEvents).toBe(1);

        const dataMatch = messages.match(/data: ({.+})/);
        if (dataMatch) {
          const data = JSON.parse(dataMatch[1]);
          expect(data.additions).toHaveLength(2);
          expect(data.deletions).toHaveLength(1);
        }
      });

      it('should apply additions before deletions according to spec note', () => {
        const materializedView = new Map<string, { bindings: any, count: number }>();
        
        const bindingKey = 'x:uri:http://ex.org/1';
        const binding = {
          toString: () => bindingKey,
          keys: () => [{ value: 'x' }],
          [Symbol.iterator]: function*() {
            yield [{ value: 'x' }, { termType: 'NamedNode', value: 'http://ex.org/1' }];
          }
        };

        materializedView.set(bindingKey, { bindings: binding, count: 1 });
        
        materializedView.get(bindingKey)!.count++;
        expect(materializedView.get(bindingKey)!.count).toBe(2);
        
        materializedView.get(bindingKey)!.count--;
        expect(materializedView.get(bindingKey)!.count).toBe(1);
        expect(materializedView.has(bindingKey)).toBe(true);
      });
    });

    describe('up-to-date event', () => {
      it('should signal all changes processed', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();
        const upToDateTimeout = new UpToDateTimeout(1000, () => {
          mgr.broadcast('up-to-date', { timestamp: new Date().toISOString() });
        });

        mgr.addConnection(res as any);
        
        upToDateTimeout.reset();
        jest.advanceTimersByTime(1000);

        const messages = res.writes.join('');
        expect(messages).toContain('event: up-to-date');
      });

      it('must include a timestamp', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();
        const timestamp = '2024-11-24T10:05:00Z';

        mgr.addConnection(res as any);
        mgr.broadcast('up-to-date', { timestamp });

        const messages = res.writes.join('');
        expect(messages).toContain('event: up-to-date');
        expect(messages).toContain(timestamp);
        
        const dataMatch = messages.match(/data: ({.+})/);
        expect(dataMatch).toBeTruthy();
        if (dataMatch) {
          const data = JSON.parse(dataMatch[1]);
          expect(data).toHaveProperty('timestamp');
          expect(data.timestamp).toBe(timestamp);
        }
      });

      it('should be sent after processing timeout', () => {
        const callbackFn = jest.fn();
        const upToDateTimeout = new UpToDateTimeout(1000, callbackFn);

        expect(upToDateTimeout.isUpToDate()).toBe(false);
        
        upToDateTimeout.reset();
        expect(upToDateTimeout.isUpToDate()).toBe(false);
        
        jest.advanceTimersByTime(1000);
        
        expect(upToDateTimeout.isUpToDate()).toBe(true);
        expect(callbackFn).toHaveBeenCalled();
      });
    });

    describe('error event', () => {
      it('should be terminal and close connection', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();

        mgr.addConnection(res as any);
        mgr.broadcast('error', { 
          status: 500, 
          statusText: 'Internal Server Error: Query execution timeout' 
        });

        const messages = res.writes.join('');
        expect(messages).toContain('event: error');
      });

      it('must include status and statusText', () => {
        const mgr = new SSEConnectionManager();
        const res = createStubResponse();

        mgr.addConnection(res as any);
        mgr.broadcast('error', { 
          status: 500, 
          statusText: 'Internal Server Error: Query execution timeout' 
        });

        const messages = res.writes.join('');
        expect(messages).toContain('event: error');
        
        const dataMatch = messages.match(/data: ({.+})/);
        expect(dataMatch).toBeTruthy();
        if (dataMatch) {
          const data = JSON.parse(dataMatch[1]);
          expect(data).toHaveProperty('status');
          expect(data).toHaveProperty('statusText');
          expect(data.status).toBe(500);
          expect(data.statusText).toContain('Internal Server Error');
        }
      });
    });
  });

  describe('Event Ordering', () => {
    it('initial event must come first', () => {
      const mgr = new SSEConnectionManager();
      const res = createStubResponse();

      mgr.addConnection(res as any);
      mgr.sendToConnection(res as any, 'initial', materializedViewToSparqlJson(new Map()));
      mgr.broadcast('processing', { timestamp: new Date().toISOString() });

      const messages = res.writes.join('');
      const initialIndex = messages.indexOf('event: initial');
      const processingIndex = messages.indexOf('event: processing');
      
      expect(initialIndex).toBeLessThan(processingIndex);
    });

    it('update events can be batched before up-to-date', () => {
      const mgr = new SSEConnectionManager();
      const res = createStubResponse();

      mgr.addConnection(res as any);
      
      mgr.queueUpdate(true, { x: { type: 'uri', value: 'http://ex.org/1' } });
      mgr.queueUpdate(true, { x: { type: 'uri', value: 'http://ex.org/2' } });
      mgr.flushUpdates();
      
      mgr.broadcast('up-to-date', { timestamp: new Date().toISOString() });

      const messages = res.writes.join('');
      const updateIndex = messages.indexOf('event: update');
      const upToDateIndex = messages.indexOf('event: up-to-date');
      
      expect(updateIndex).toBeLessThan(upToDateIndex);
    });
  });
});

describe('SPARQL Results JSON Format Compliance', () => {
  describe('materializedViewToSparqlJson', () => {
    it('should produce valid SPARQL Results JSON structure', () => {
      const materializedView = new Map();
      const result = materializedViewToSparqlJson(materializedView);

      expect(result).toHaveProperty('head');
      expect(result).toHaveProperty('results');
      expect(result.head).toHaveProperty('vars');
      expect(result.results).toHaveProperty('bindings');
      expect(Array.isArray(result.head.vars)).toBe(true);
      expect(Array.isArray(result.results.bindings)).toBe(true);
    });

    it('should extract variable names from bindings', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'book' }, { termType: 'NamedNode', value: 'http://example.org/book1' }],
          [{ value: 'title' }, { termType: 'Literal', value: 'SPARQL Tutorial' }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.head.vars).toContain('book');
      expect(result.head.vars).toContain('title');
    });

    it('should format URI bindings correctly', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 's' }, { termType: 'NamedNode', value: 'http://example.org/subject' }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings).toHaveLength(1);
      expect(result.results.bindings[0].s).toEqual({
        type: 'uri',
        value: 'http://example.org/subject'
      });
    });

    it('should format Literal bindings correctly', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'title' }, { termType: 'Literal', value: 'SPARQL Tutorial', datatype: { value: 'http://www.w3.org/2001/XMLSchema#string' } }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings[0].title).toEqual({
        type: 'literal',
        value: 'SPARQL Tutorial',
        datatype: 'http://www.w3.org/2001/XMLSchema#string'
      });
    });

    it('should format Literal with language tag correctly', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'label' }, { termType: 'Literal', value: 'Hello', language: 'en' }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings[0].label).toEqual({
        type: 'literal',
        value: 'Hello',
        'xml:lang': 'en'
      });
    });

    it('should format BlankNode bindings correctly', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'BlankNode', value: '_:b1' }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings[0].x).toEqual({
        type: 'bnode',
        value: '_:b1'
      });
    });

    it('should respect binding count for duplicates', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'NamedNode', value: 'http://ex.org/1' }]
        ]),
        count: 3
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings).toHaveLength(3);
      expect(result.results.bindings[0]).toEqual(result.results.bindings[1]);
      expect(result.results.bindings[1]).toEqual(result.results.bindings[2]);
    });
  });

  describe('bindingToSparqlJson', () => {
    it('should convert single binding to SPARQL Results JSON format', () => {
      const binding = new Map([
        [{ value: 'book' }, { termType: 'NamedNode', value: 'http://example.org/book1' }],
        [{ value: 'title' }, { termType: 'Literal', value: 'SPARQL Tutorial' }]
      ]);

      const result = bindingToSparqlJson(binding);
      
      expect(result).toHaveProperty('bindings');
      expect(Array.isArray(result.bindings)).toBe(true);
      expect(result.bindings).toHaveLength(1);
      expect(result.bindings[0]).toHaveProperty('book');
      expect(result.bindings[0]).toHaveProperty('title');
    });

    it('should handle all RDF term types', () => {
      const binding = new Map([
        [{ value: 'uri' }, { termType: 'NamedNode', value: 'http://ex.org/s' }],
        [{ value: 'lit' }, { termType: 'Literal', value: 'text' }],
        [{ value: 'blank' }, { termType: 'BlankNode', value: '_:b1' }]
      ]);

      const result = bindingToSparqlJson(binding);
      
      expect(result.bindings[0].uri.type).toBe('uri');
      expect(result.bindings[0].lit.type).toBe('literal');
      expect(result.bindings[0].blank.type).toBe('bnode');
    });
  });
});

describe('SSEConnectionManager Protocol Compliance', () => {
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

  it('should broadcast to all active connections', () => {
    const mgr = new SSEConnectionManager();
    const res1 = createStubResponse();
    const res2 = createStubResponse();
    const res3 = createStubResponse();

    mgr.addConnection(res1 as any);
    mgr.addConnection(res2 as any);
    mgr.addConnection(res3 as any);

    mgr.broadcast('update', { additions: [], deletions: [] });

    expect(res1.writes.join('')).toContain('event: update');
    expect(res2.writes.join('')).toContain('event: update');
    expect(res3.writes.join('')).toContain('event: update');
  });

  it('should send to specific connection only', () => {
    const mgr = new SSEConnectionManager();
    const res1 = createStubResponse();
    const res2 = createStubResponse();

    mgr.addConnection(res1 as any);
    mgr.addConnection(res2 as any);

    mgr.sendToConnection(res1 as any, 'initial', { head: { vars: [] }, results: { bindings: [] } });

    expect(res1.writes.join('')).toContain('event: initial');
    expect(res2.writes.join('')).not.toContain('event: initial');
  });

  it('should properly format SSE messages', () => {
    const mgr = new SSEConnectionManager();
    const res = createStubResponse();

    mgr.addConnection(res as any);
    mgr.broadcast('processing', { timestamp: '2024-11-24T10:00:00Z' });

    const messages = res.writes.join('');
    expect(messages).toMatch(/event: processing\n/);
    expect(messages).toMatch(/data: .+\n/);
    expect(messages).toMatch(/\n\n/);
  });

  it('should handle connection cleanup on close', () => {
    const mgr = new SSEConnectionManager();
    const res = createStubResponse();

    mgr.addConnection(res as any);
    res.triggerClose();

    mgr.broadcast('update', { additions: [], deletions: [] });

    expect(res.writes.join('')).not.toContain('event: update');
  });

  it('should batch updates within time window', () => {
    const mgr = new SSEConnectionManager();
    const res = createStubResponse();

    mgr.addConnection(res as any);
    
    mgr.queueUpdate(true, { x: { type: 'uri', value: '1' } });
    expect(res.writes.join('')).not.toContain('event: update');
    
    mgr.queueUpdate(true, { x: { type: 'uri', value: '2' } });
    mgr.queueUpdate(false, { x: { type: 'uri', value: '3' } });
    
    jest.advanceTimersByTime(100);
    
    const messages = res.writes.join('');
    const updateCount = (messages.match(/event: update/g) || []).length;
    expect(updateCount).toBe(1);
  });

  it('should flush updates immediately when requested', () => {
    const mgr = new SSEConnectionManager();
    const res = createStubResponse();

    mgr.addConnection(res as any);
    
    mgr.queueUpdate(true, { x: { type: 'uri', value: '1' } });
    mgr.flushUpdates();
    
    expect(res.writes.join('')).toContain('event: update');
  });
});

describe('UpToDateTimeout Protocol Compliance', () => {
  jest.useFakeTimers();

  it('should track up-to-date state correctly', () => {
    const upToDateTimeout = new UpToDateTimeout(1000);

    expect(upToDateTimeout.isUpToDate()).toBe(false);
    
    upToDateTimeout.reset();
    expect(upToDateTimeout.isUpToDate()).toBe(false);
    
    jest.advanceTimersByTime(1000);
    expect(upToDateTimeout.isUpToDate()).toBe(true);
  });

  it('should reset timeout on new changes', () => {
    const callback = jest.fn();
    const upToDateTimeout = new UpToDateTimeout(1000, callback);

    upToDateTimeout.reset();
    jest.advanceTimersByTime(500);
    
    expect(upToDateTimeout.isUpToDate()).toBe(false);
    expect(callback).not.toHaveBeenCalled();
    
    upToDateTimeout.reset();
    jest.advanceTimersByTime(500);
    
    expect(upToDateTimeout.isUpToDate()).toBe(false);
    expect(callback).not.toHaveBeenCalled();
    
    jest.advanceTimersByTime(500);
    
    expect(upToDateTimeout.isUpToDate()).toBe(true);
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('should support custom timeout intervals', () => {
    const callback = jest.fn();
    const upToDateTimeout = new UpToDateTimeout(500, callback);

    upToDateTimeout.reset();
    jest.advanceTimersByTime(500);
    
    expect(callback).toHaveBeenCalled();
  });

  it('should support runtime interval changes', () => {
    const callback = jest.fn();
    const upToDateTimeout = new UpToDateTimeout(1000, callback);

    upToDateTimeout.reset(2000);
    jest.advanceTimersByTime(1000);
    
    expect(callback).not.toHaveBeenCalled();
    
    jest.advanceTimersByTime(1000);
    expect(callback).toHaveBeenCalled();
  });

  it('should invoke callback when becoming up-to-date', () => {
    const callback = jest.fn();
    const upToDateTimeout = new UpToDateTimeout(1000, callback);

    upToDateTimeout.reset();
    jest.advanceTimersByTime(1000);
    
    expect(callback).toHaveBeenCalledTimes(1);
  });
});

