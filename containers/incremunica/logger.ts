import pino from 'pino';

// Accept both LOG_LEVEL and LOG-LEVEL env vars. Default: 'silent' (no logs).
// Map custom levels to pino levels. Pino built-in levels:
// trace (10) debug (20) info (30) warn (40) error (50) fatal (60) silent
const raw = (process.env.LOG_LEVEL || process.env['LOG-LEVEL'] || 'silent').toLowerCase();

// Normalize allowed aliases
const aliasMap: Record<string, pino.LevelWithSilent> = {
  off: 'silent',
  none: 'silent',
  error: 'error',
  warn: 'warn',
  warning: 'warn',
  info: 'info',
  debug: 'debug',
  trace: 'trace',
  fatal: 'fatal',
  silent: 'silent'
};
const level: pino.LevelWithSilent = aliasMap[raw] ?? 'silent';

export const logger = pino({
  level,
  base: undefined, // no pid/hostname clutter by default
  timestamp: pino.stdTimeFunctions.isoTime,
});

logger.debug({ level }, 'Logger initialized');

