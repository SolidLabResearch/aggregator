describe('SSE Message Parsing - Protocol Compliance', () => {
  describe('SSE Message Format', () => {
    it('should parse event field correctly', () => {
      const message = 'event: initial\ndata: {}\n\n';
      const lines = message.split('\n');

      let currentEvent: string | null = null;
      let currentData: string | null = null;

      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          currentData = line.slice(6).trim();
        }
      }

      expect(currentEvent).toBe('initial');
      expect(currentData).toBe('{}');
    });

    it('should handle multi-line data fields', () => {
      const message = 'event: update\ndata: line1\ndata: line2\n\n';
      const lines = message.split('\n');

      let currentEvent: string | null = null;
      const dataLines: string[] = [];

      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          dataLines.push(line.slice(6).trim());
        }
      }

      expect(currentEvent).toBe('update');
      expect(dataLines).toHaveLength(2);
      expect(dataLines[0]).toBe('line1');
      expect(dataLines[1]).toBe('line2');
    });

    it('should recognize message boundary with empty line', () => {
      const stream = 'event: initial\ndata: {}\n\nevent: processing\ndata: {}\n\n';
      const messages = stream.split('\n\n').filter(m => m.length > 0);

      expect(messages).toHaveLength(2);
      expect(messages[0]).toContain('event: initial');
      expect(messages[1]).toContain('event: processing');
    });

    it('should handle streaming buffer correctly', () => {
      let buffer = '';
      const chunks = ['event: init', 'ial\ndata: {}\n\n'];

      for (const chunk of chunks) {
        buffer += chunk;
      }

      const lines = buffer.split('\n');
      expect(lines.some(l => l.startsWith('event: initial'))).toBe(true);
    });

    it('should parse complete SSE event with all fields', () => {
      const message = 'event: update\ndata: {"additions":[],"deletions":[]}\n\n';

      let currentEvent: string | null = null;
      let currentData: string | null = null;

      const lines = message.split('\n');
      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          currentData = line.slice(6).trim();
        } else if (line === '' && currentEvent && currentData) {
          expect(currentEvent).toBe('update');
          expect(JSON.parse(currentData)).toHaveProperty('additions');
          expect(JSON.parse(currentData)).toHaveProperty('deletions');
        }
      }
    });
  });

  describe('SSE Stream Processing', () => {
    it('should handle incomplete messages in buffer', () => {
      let buffer = '';

      buffer += 'event: initial\ndata: {';
      const lines1 = buffer.split('\n');
      const remaining1 = lines1.pop() || '';
      expect(remaining1).toBe('data: {');

      buffer = remaining1 + '}\n\n';
      const lines2 = buffer.split('\n');
      const remaining2 = lines2.pop() || '';
      expect(remaining2).toBe('');

      const fullMessage = lines1.concat(lines2).join('\n');
      expect(fullMessage).toContain('event: initial');
      expect(fullMessage).toContain('data: {}');
    });

    it('should process multiple events in single chunk', () => {
      const chunk = 'event: update\ndata: {}\n\nevent: up-to-date\ndata: {}\n\n';
      const messages = chunk.split('\n\n').filter(m => m.length > 0);

      expect(messages).toHaveLength(2);
      expect(messages[0]).toContain('event: update');
      expect(messages[1]).toContain('event: up-to-date');
    });

    it('should handle empty lines within event data', () => {
      let currentEvent: string | null = null;
      let currentData: string | null = null;
      const events: Array<{event: string, data: string}> = [];

      const lines = 'event: test\ndata: line1\n\ndata: line2\n\n'.split('\n');

      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          currentData = line.slice(6).trim();
        } else if (line === '' && currentEvent && currentData) {
          events.push({event: currentEvent, data: currentData});
          currentEvent = null;
          currentData = null;
        }
      }

      expect(events).toHaveLength(1);
      expect(events[0].event).toBe('test');
    });
  });

  describe('Event Type Detection', () => {
    const eventTypes = ['initial', 'processing', 'update', 'up-to-date', 'error'];

    eventTypes.forEach(eventType => {
      it(`should detect ${eventType} event type`, () => {
        const message = `event: ${eventType}\ndata: {}\n\n`;
        const eventMatch = message.match(/event: ([\w-]+)/);

        expect(eventMatch).toBeTruthy();
        if (eventMatch) {
          expect(eventMatch[1]).toBe(eventType);
        }
      });
    });

    it('should ignore unknown event types but still parse them', () => {
      const message = 'event: custom-event\ndata: {}\n\n';
      const lines = message.split('\n');

      let currentEvent: string | null = null;

      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7).trim();
        }
      }

      expect(currentEvent).toBe('custom-event');
    });
  });

  describe('Data Parsing', () => {
    it('should parse JSON data in initial event', () => {
      const data = JSON.stringify({
        head: { vars: ['book', 'title'] },
        results: { bindings: [] }
      });
      const message = `event: initial\ndata: ${data}\n\n`;

      const dataMatch = message.match(/data: (.+)/);
      expect(dataMatch).toBeTruthy();

      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed).toHaveProperty('head');
        expect(parsed).toHaveProperty('results');
      }
    });

    it('should parse JSON data in processing event', () => {
      const data = JSON.stringify({ timestamp: '2024-11-24T10:00:00Z' });
      const message = `event: processing\ndata: ${data}\n\n`;

      const dataMatch = message.match(/data: (.+)/);
      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed).toHaveProperty('timestamp');
        expect(parsed.timestamp).toBe('2024-11-24T10:00:00Z');
      }
    });

    it('should parse JSON data in update event', () => {
      const data = JSON.stringify({
        additions: [{ x: { type: 'uri', value: 'http://ex.org/1' } }],
        deletions: [{ x: { type: 'uri', value: 'http://ex.org/2' } }]
      });
      const message = `event: update\ndata: ${data}\n\n`;

      const dataMatch = message.match(/data: (.+)/);
      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed).toHaveProperty('additions');
        expect(parsed).toHaveProperty('deletions');
        expect(Array.isArray(parsed.additions)).toBe(true);
        expect(Array.isArray(parsed.deletions)).toBe(true);
      }
    });

    it('should parse JSON data in up-to-date event', () => {
      const data = JSON.stringify({ timestamp: '2024-11-24T10:05:00Z' });
      const message = `event: up-to-date\ndata: ${data}\n\n`;

      const dataMatch = message.match(/data: (.+)/);
      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed).toHaveProperty('timestamp');
      }
    });

    it('should parse JSON data in error event', () => {
      const data = JSON.stringify({
        status: 500,
        statusText: 'Internal Server Error'
      });
      const message = `event: error\ndata: ${data}\n\n`;

      const dataMatch = message.match(/data: (.+)/);
      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed).toHaveProperty('status');
        expect(parsed).toHaveProperty('statusText');
        expect(parsed.status).toBe(500);
      }
    });
  });

  describe('Timestamp Format Validation', () => {
    it('should validate ISO 8601 timestamp format', () => {
      const timestamp = '2024-11-24T10:00:00Z';
      const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;

      expect(isoRegex.test(timestamp)).toBe(true);
    });

    it('should validate ISO 8601 timestamp with milliseconds', () => {
      const timestamp = '2024-11-24T10:00:00.123Z';
      const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;

      expect(isoRegex.test(timestamp)).toBe(true);
    });

    it('should validate timestamp is parseable', () => {
      const timestamp = '2024-11-24T10:00:00Z';
      const date = new Date(timestamp);

      expect(isNaN(date.getTime())).toBe(false);
      expect(date.toISOString()).toContain('2024-11-24T10:00:00');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty data field', () => {
      const message = 'event: processing\ndata: \n\n';
      const lines = message.split('\n');

      let currentData: string | null = null;

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          currentData = line.slice(6).trim();
        }
      }

      expect(currentData).toBe('');
    });

    it('should handle data without event field', () => {
      const message = 'data: {}\n\n';
      const lines = message.split('\n');

      let currentEvent: string | null = null;
      let currentData: string | null = null;

      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          currentData = line.slice(6).trim();
        }
      }

      expect(currentEvent).toBeNull();
      expect(currentData).toBe('{}');
    });

    it('should handle whitespace in event names', () => {
      const message = 'event:   up-to-date  \ndata: {}\n\n';
      const eventMatch = message.match(/event:\s*(.+)/);

      if (eventMatch) {
        const eventName = eventMatch[1].trim();
        expect(eventName).toBe('up-to-date');
      }
    });

    it('should handle colon in data field', () => {
      const data = JSON.stringify({ url: 'http://example.org' });
      const message = `event: update\ndata: ${data}\n\n`;

      const dataMatch = message.match(/data: (.+)/);
      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed.url).toBe('http://example.org');
      }
    });
  });

  describe('Stream Continuation', () => {
    it('should maintain state across multiple chunks', () => {
      const decoder = new TextDecoder();
      let buffer = '';

      const chunk1 = new Uint8Array([101, 118, 101, 110, 116, 58, 32, 105, 110, 105, 116]); // "event: init"
      const chunk2 = new Uint8Array([105, 97, 108, 10, 100, 97, 116, 97, 58, 32, 123, 125, 10, 10]); // "ial\ndata: {}\n\n"

      buffer += decoder.decode(chunk1, { stream: true });
      buffer += decoder.decode(chunk2, { stream: true });

      const lines = buffer.split('\n');
      expect(lines[0]).toBe('event: initial');
      expect(lines[1]).toBe('data: {}');
    });

    it('should preserve buffer remainder after processing', () => {
      let buffer = 'event: initial\ndata: {}\n\nevent: proc';

      const lines = buffer.split('\n');
      const remainder = lines.pop() || '';

      expect(remainder).toBe('event: proc');

      buffer = remainder + 'essing\ndata: {}\n\n';
      const newLines = buffer.split('\n');

      expect(newLines[0]).toBe('event: processing');
    });
  });

  describe('Protocol Compliance - Error Handling', () => {
    it('should handle malformed JSON gracefully', () => {
      const message = 'event: update\ndata: {invalid json}\n\n';
      const dataMatch = message.match(/data: (.+)/);

      if (dataMatch) {
        expect(() => JSON.parse(dataMatch[1])).toThrow();
      }
    });

    it('should handle missing required fields in event data', () => {
      const message = 'event: up-to-date\ndata: {}\n\n';
      const dataMatch = message.match(/data: (.+)/);

      if (dataMatch) {
        const parsed = JSON.parse(dataMatch[1]);
        expect(parsed.timestamp).toBeUndefined();
      }
    });

    it('should continue processing after encountering unknown event', () => {
      const stream = 'event: unknown\ndata: {}\n\nevent: up-to-date\ndata: {"timestamp":"2024-11-24T10:00:00Z"}\n\n';
      const messages = stream.split('\n\n').filter(m => m.length > 0);

      expect(messages).toHaveLength(2);
      expect(messages[1]).toContain('event: up-to-date');
    });
  });
});

describe('SSE Client Behavior - Implementation Tests', () => {
  describe('EventSource-like Behavior', () => {
    it('should process events in order', () => {
      const events: string[] = [];
      const stream = `event: initial\ndata: {}\n\nevent: processing\ndata: {}\n\nevent: update\ndata: {}\n\nevent: up-to-date\ndata: {}\n\n`;

      const messages = stream.split('\n\n').filter(m => m.length > 0);
      messages.forEach(msg => {
        const eventMatch = msg.match(/event: (\S+)/);
        if (eventMatch) {
          events.push(eventMatch[1]);
        }
      });

      expect(events).toEqual(['initial', 'processing', 'update', 'up-to-date']);
    });

    it('should handle connection close cleanly', () => {
      let isClosed = false;
      const buffer = 'event: initial\ndata: {}\n\n';

      const cleanup = () => {
        isClosed = true;
      };

      expect(isClosed).toBe(false);
      cleanup();
      expect(isClosed).toBe(true);
    });

    it('should not process events after close', () => {
      let isClosed = false;
      const events: string[] = [];

      const processEvent = (event: string) => {
        if (!isClosed) {
          events.push(event);
        }
      };

      processEvent('initial');
      processEvent('processing');

      isClosed = true;

      processEvent('update');
      processEvent('up-to-date');

      expect(events).toEqual(['initial', 'processing']);
    });
  });

  describe('Backpressure Handling', () => {
    it('should batch rapid updates', () => {
      const updates: any[] = [];
      const batchSize = 3;
      let pendingBatch: any[] = [];

      const queueUpdate = (update: any) => {
        pendingBatch.push(update);
        if (pendingBatch.length >= batchSize) {
          updates.push([...pendingBatch]);
          pendingBatch = [];
        }
      };

      queueUpdate({ x: 1 });
      queueUpdate({ x: 2 });
      queueUpdate({ x: 3 });

      expect(updates).toHaveLength(1);
      expect(updates[0]).toHaveLength(3);
    });

    it('should flush pending updates on timeout', () => {
      jest.useFakeTimers();

      const updates: any[] = [];
      let pendingBatch: any[] = [];
      let timeout: NodeJS.Timeout | undefined;

      const queueUpdate = (update: any) => {
        pendingBatch.push(update);

        if (timeout) clearTimeout(timeout);

        timeout = setTimeout(() => {
          if (pendingBatch.length > 0) {
            updates.push([...pendingBatch]);
            pendingBatch = [];
          }
        }, 100);
      };

      queueUpdate({ x: 1 });
      queueUpdate({ x: 2 });

      expect(updates).toHaveLength(0);

      jest.advanceTimersByTime(100);

      expect(updates).toHaveLength(1);
      expect(updates[0]).toHaveLength(2);

      jest.useRealTimers();
    });
  });
});

