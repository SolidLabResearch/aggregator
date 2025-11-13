import { jest } from '@jest/globals';

describe('logger configuration via env', () => {
  const OLD_ENV = process.env as NodeJS.ProcessEnv;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...OLD_ENV };
  });
  afterEach(() => {
    process.env = OLD_ENV;
  });

  it('defaults to silent/off when no env provided', async () => {
    delete process.env.LOG_LEVEL;
    delete (process.env as any)['LOG-LEVEL'];
    const { logger } = await import('../logger');
    expect(logger.level).toBe('silent');
  });

  it('accepts LOG_LEVEL=debug', async () => {
    process.env.LOG_LEVEL = 'debug';
    const { logger } = await import('../logger');
    expect(logger.level).toBe('debug');
  });

  it('accepts LOG-LEVEL=warning alias mapped to warn', async () => {
    (process.env as any)['LOG-LEVEL'] = 'warning';
    const { logger } = await import('../logger');
    expect(logger.level).toBe('warn');
  });

  it('maps off/none to silent', async () => {
    process.env.LOG_LEVEL = 'off';
    let mod = await import('../logger');
    expect(mod.logger.level).toBe('silent');

    jest.resetModules();
    process.env.LOG_LEVEL = 'none';
    mod = await import('../logger');
    expect(mod.logger.level).toBe('silent');
  });
});
