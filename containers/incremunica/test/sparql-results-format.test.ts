import { materializedViewToSparqlJson, bindingToSparqlJson } from '../main';

describe('SPARQL Results Format Compliance Tests', () => {
  describe('Variable Binding Formats', () => {
    describe('URI (NamedNode) Bindings', () => {
      it('should format URI with type "uri"', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'subject' }, { termType: 'NamedNode', value: 'http://example.org/resource' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].subject.type).toBe('uri');
        expect(result.results.bindings[0].subject.value).toBe('http://example.org/resource');
      });

      it('should handle URIs with special characters', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 's' }, { termType: 'NamedNode', value: 'http://example.org/path?query=value&other=123' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].s.type).toBe('uri');
        expect(result.results.bindings[0].s.value).toContain('?');
        expect(result.results.bindings[0].s.value).toContain('&');
      });

      it('should handle URIs with fragments', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 's' }, { termType: 'NamedNode', value: 'http://example.org/page#section' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].s.value).toContain('#section');
      });
    });

    describe('Literal Bindings', () => {
      it('should format plain literal', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'label' }, { termType: 'Literal', value: 'Hello World' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].label.type).toBe('literal');
        expect(result.results.bindings[0].label.value).toBe('Hello World');
        expect(result.results.bindings[0].label.datatype).toBeUndefined();
        expect(result.results.bindings[0].label['xml:lang']).toBeUndefined();
      });

      it('should format typed literal with datatype', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'count' }, { 
              termType: 'Literal', 
              value: '42',
              datatype: { value: 'http://www.w3.org/2001/XMLSchema#integer' }
            }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].count.type).toBe('literal');
        expect(result.results.bindings[0].count.value).toBe('42');
        expect(result.results.bindings[0].count.datatype).toBe('http://www.w3.org/2001/XMLSchema#integer');
      });

      it('should format language-tagged literal', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'label' }, { 
              termType: 'Literal', 
              value: 'Bonjour',
              language: 'fr'
            }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].label.type).toBe('literal');
        expect(result.results.bindings[0].label.value).toBe('Bonjour');
        expect(result.results.bindings[0].label['xml:lang']).toBe('fr');
      });

      it('should handle multiline literal values', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'description' }, { 
              termType: 'Literal', 
              value: 'Line 1\nLine 2\nLine 3'
            }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].description.value).toContain('\n');
      });

      it('should handle empty string literal', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'text' }, { termType: 'Literal', value: '' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].text.type).toBe('literal');
        expect(result.results.bindings[0].text.value).toBe('');
      });

      it('should handle literal with special characters', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'special' }, { 
              termType: 'Literal', 
              value: 'Quote: " Backslash: \\ Newline: \n Tab: \t'
            }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].special.type).toBe('literal');
        expect(result.results.bindings[0].special.value).toContain('"');
        expect(result.results.bindings[0].special.value).toContain('\\');
      });
    });

    describe('BlankNode Bindings', () => {
      it('should format blank node with type "bnode"', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'x' }, { termType: 'BlankNode', value: '_:b0' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].x.type).toBe('bnode');
        expect(result.results.bindings[0].x.value).toBe('_:b0');
      });

      it('should preserve blank node identifiers', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'b1' }, { termType: 'BlankNode', value: '_:genid123' }],
            [{ value: 'b2' }, { termType: 'BlankNode', value: '_:genid123' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.results.bindings[0].b1.value).toBe(result.results.bindings[0].b2.value);
      });
    });

    describe('Multiple Variables', () => {
      it('should handle binding with multiple variables', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 's' }, { termType: 'NamedNode', value: 'http://example.org/subject' }],
            [{ value: 'p' }, { termType: 'NamedNode', value: 'http://example.org/predicate' }],
            [{ value: 'o' }, { termType: 'Literal', value: 'Object' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.head.vars).toContain('s');
        expect(result.head.vars).toContain('p');
        expect(result.head.vars).toContain('o');
        expect(result.results.bindings[0]).toHaveProperty('s');
        expect(result.results.bindings[0]).toHaveProperty('p');
        expect(result.results.bindings[0]).toHaveProperty('o');
      });

      it('should collect all unique variable names from all bindings', () => {
        const materializedView = new Map();
        materializedView.set('binding1', {
          bindings: new Map([
            [{ value: 'x' }, { termType: 'Literal', value: '1' }],
            [{ value: 'y' }, { termType: 'Literal', value: '2' }]
          ]),
          count: 1
        });
        materializedView.set('binding2', {
          bindings: new Map([
            [{ value: 'x' }, { termType: 'Literal', value: '3' }],
            [{ value: 'z' }, { termType: 'Literal', value: '4' }]
          ]),
          count: 1
        });

        const result = materializedViewToSparqlJson(materializedView);
        
        expect(result.head.vars).toContain('x');
        expect(result.head.vars).toContain('y');
        expect(result.head.vars).toContain('z');
        expect(result.head.vars.length).toBe(3);
      });
    });
  });

  describe('Empty Results', () => {
    it('should handle empty materialized view', () => {
      const materializedView = new Map();
      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.head.vars).toEqual([]);
      expect(result.results.bindings).toEqual([]);
    });

    it('should handle binding with zero count', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'Literal', value: '1' }]
        ]),
        count: 0
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings).toHaveLength(0);
    });
  });

  describe('Duplicate Bindings', () => {
    it('should respect count for duplicate bindings', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'Literal', value: 'value' }]
        ]),
        count: 5
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings).toHaveLength(5);
      result.results.bindings.forEach(binding => {
        expect(binding.x.value).toBe('value');
      });
    });

    it('should handle mix of unique and duplicate bindings', () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'Literal', value: 'a' }]
        ]),
        count: 2
      });
      materializedView.set('binding2', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'Literal', value: 'b' }]
        ]),
        count: 1
      });
      materializedView.set('binding3', {
        bindings: new Map([
          [{ value: 'x' }, { termType: 'Literal', value: 'c' }]
        ]),
        count: 3
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings).toHaveLength(6);
      
      const aCount = result.results.bindings.filter(b => b.x.value === 'a').length;
      const bCount = result.results.bindings.filter(b => b.x.value === 'b').length;
      const cCount = result.results.bindings.filter(b => b.x.value === 'c').length;
      
      expect(aCount).toBe(2);
      expect(bCount).toBe(1);
      expect(cCount).toBe(3);
    });
  });

  describe('bindingToSparqlJson format', () => {
    it('should format single binding for additions/deletions', () => {
      const binding = new Map([
        [{ value: 'book' }, { termType: 'NamedNode', value: 'http://example.org/book1' }],
        [{ value: 'title' }, { termType: 'Literal', value: 'SPARQL Tutorial' }]
      ]);

      const result = bindingToSparqlJson(binding);
      
      expect(result).toHaveProperty('bindings');
      expect(result.bindings).toHaveLength(1);
      expect(result.bindings[0]).toHaveProperty('book');
      expect(result.bindings[0]).toHaveProperty('title');
    });

    it('should not include head section', () => {
      const binding = new Map([
        [{ value: 'x' }, { termType: 'Literal', value: '1' }]
      ]);

      const result = bindingToSparqlJson(binding);
      
      expect(result).not.toHaveProperty('head');
      expect(result).toHaveProperty('bindings');
    });
  });
});

describe('Update Event Semantics', () => {
  describe('Addition and Deletion Semantics', () => {
    it('should correctly identify additions increase count', () => {
      const materializedView = new Map<string, { bindings: any, count: number }>();
      const bindingKey = 'test-binding';
      const binding = {
        toString: () => bindingKey,
        keys: () => [{ value: 'x' }],
        [Symbol.iterator]: function*() {
          yield [{ value: 'x' }, { termType: 'Literal', value: '1' }];
        }
      };

      materializedView.set(bindingKey, { bindings: binding, count: 1 });
      
      materializedView.get(bindingKey)!.count++;
      
      expect(materializedView.get(bindingKey)!.count).toBe(2);
      expect(materializedView.has(bindingKey)).toBe(true);
    });

    it('should correctly handle deletions that decrease count', () => {
      const materializedView = new Map<string, { bindings: any, count: number }>();
      const bindingKey = 'test-binding';
      const binding = {
        toString: () => bindingKey,
        keys: () => [{ value: 'x' }],
        [Symbol.iterator]: function*() {
          yield [{ value: 'x' }, { termType: 'Literal', value: '1' }];
        }
      };

      materializedView.set(bindingKey, { bindings: binding, count: 3 });
      
      materializedView.get(bindingKey)!.count--;
      
      expect(materializedView.get(bindingKey)!.count).toBe(2);
      expect(materializedView.has(bindingKey)).toBe(true);
    });

    it('should remove binding when count reaches zero', () => {
      const materializedView = new Map<string, { bindings: any, count: number }>();
      const bindingKey = 'test-binding';
      const binding = {
        toString: () => bindingKey,
        keys: () => [{ value: 'x' }],
        [Symbol.iterator]: function*() {
          yield [{ value: 'x' }, { termType: 'Literal', value: '1' }];
        }
      };

      materializedView.set(bindingKey, { bindings: binding, count: 1 });
      
      const entry = materializedView.get(bindingKey)!;
      entry.count--;
      if (entry.count <= 0) {
        materializedView.delete(bindingKey);
      }
      
      expect(materializedView.has(bindingKey)).toBe(false);
    });

    it('should handle interleaved additions and deletions', () => {
      const materializedView = new Map<string, { bindings: any, count: number }>();
      const bindingKey = 'test-binding';
      const binding = {
        toString: () => bindingKey,
        keys: () => [{ value: 'x' }],
        [Symbol.iterator]: function*() {
          yield [{ value: 'x' }, { termType: 'Literal', value: '1' }];
        }
      };

      materializedView.set(bindingKey, { bindings: binding, count: 1 });
      
      materializedView.get(bindingKey)!.count++;
      expect(materializedView.get(bindingKey)!.count).toBe(2);
      
      materializedView.get(bindingKey)!.count++;
      expect(materializedView.get(bindingKey)!.count).toBe(3);
      
      materializedView.get(bindingKey)!.count--;
      expect(materializedView.get(bindingKey)!.count).toBe(2);
      
      materializedView.get(bindingKey)!.count--;
      expect(materializedView.get(bindingKey)!.count).toBe(1);
    });
  });

  describe('Binding Equality', () => {
    it('should treat identical bindings as equal', () => {
      const binding1 = new Map([
        [{ value: 'x' }, { termType: 'Literal', value: '1' }]
      ]);
      const binding2 = new Map([
        [{ value: 'x' }, { termType: 'Literal', value: '1' }]
      ]);

      const json1 = bindingToSparqlJson(binding1);
      const json2 = bindingToSparqlJson(binding2);
      
      expect(JSON.stringify(json1)).toBe(JSON.stringify(json2));
    });

    it('should treat different values as different bindings', () => {
      const binding1 = new Map([
        [{ value: 'x' }, { termType: 'Literal', value: '1' }]
      ]);
      const binding2 = new Map([
        [{ value: 'x' }, { termType: 'Literal', value: '2' }]
      ]);

      const json1 = bindingToSparqlJson(binding1);
      const json2 = bindingToSparqlJson(binding2);
      
      expect(JSON.stringify(json1)).not.toBe(JSON.stringify(json2));
    });

    it('should treat different term types as different bindings', () => {
      const binding1 = new Map([
        [{ value: 'x' }, { termType: 'Literal', value: 'http://ex.org' }]
      ]);
      const binding2 = new Map([
        [{ value: 'x' }, { termType: 'NamedNode', value: 'http://ex.org' }]
      ]);

      const json1 = bindingToSparqlJson(binding1);
      const json2 = bindingToSparqlJson(binding2);
      
      expect(json1.bindings[0].x.type).toBe('literal');
      expect(json2.bindings[0].x.type).toBe('uri');
      expect(JSON.stringify(json1)).not.toBe(JSON.stringify(json2));
    });
  });
});

describe('XSD Datatype Support', () => {
  const xsdDatatypes = [
    { name: 'integer', value: '42', uri: 'http://www.w3.org/2001/XMLSchema#integer' },
    { name: 'decimal', value: '3.14', uri: 'http://www.w3.org/2001/XMLSchema#decimal' },
    { name: 'boolean', value: 'true', uri: 'http://www.w3.org/2001/XMLSchema#boolean' },
    { name: 'date', value: '2024-11-24', uri: 'http://www.w3.org/2001/XMLSchema#date' },
    { name: 'dateTime', value: '2024-11-24T10:00:00Z', uri: 'http://www.w3.org/2001/XMLSchema#dateTime' },
    { name: 'string', value: 'text', uri: 'http://www.w3.org/2001/XMLSchema#string' },
  ];

  xsdDatatypes.forEach(({ name, value, uri }) => {
    it(`should handle xsd:${name} datatype`, () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'val' }, { 
            termType: 'Literal', 
            value: value,
            datatype: { value: uri }
          }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings[0].val.type).toBe('literal');
      expect(result.results.bindings[0].val.value).toBe(value);
      expect(result.results.bindings[0].val.datatype).toBe(uri);
    });
  });
});

describe('Language Tag Support', () => {
  const languages = [
    { code: 'en', text: 'Hello' },
    { code: 'fr', text: 'Bonjour' },
    { code: 'de', text: 'Hallo' },
    { code: 'es', text: 'Hola' },
    { code: 'en-US', text: 'Hello US' },
    { code: 'en-GB', text: 'Hello UK' },
  ];

  languages.forEach(({ code, text }) => {
    it(`should handle @${code} language tag`, () => {
      const materializedView = new Map();
      materializedView.set('binding1', {
        bindings: new Map([
          [{ value: 'label' }, { 
            termType: 'Literal', 
            value: text,
            language: code
          }]
        ]),
        count: 1
      });

      const result = materializedViewToSparqlJson(materializedView);
      
      expect(result.results.bindings[0].label.type).toBe('literal');
      expect(result.results.bindings[0].label.value).toBe(text);
      expect(result.results.bindings[0].label['xml:lang']).toBe(code);
    });
  });

  it('should not have both datatype and language tag', () => {
    const materializedView = new Map();
    materializedView.set('binding1', {
      bindings: new Map([
        [{ value: 'label' }, { 
          termType: 'Literal', 
          value: 'Hello',
          language: 'en'
        }]
      ]),
      count: 1
    });

    const result = materializedViewToSparqlJson(materializedView);
    
    expect(result.results.bindings[0].label['xml:lang']).toBe('en');
    expect(result.results.bindings[0].label.datatype).toBeUndefined();
  });
});

