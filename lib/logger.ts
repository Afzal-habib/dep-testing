/**
 * Environment-aware logger utility
 * 
 * This logger provides consistent logging across the application while:
 * - Only outputting debug logs in development mode
 * - Always outputting errors and warnings
 * - Providing structured logging with prefixes
 * 
 * Usage:
 *   import { logger } from '@/lib/logger'
 *   logger.debug('Some debug info', data)
 *   logger.info('Some info', data)
 *   logger.warn('Some warning', data)
 *   logger.error('Some error', error)
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error'

interface LoggerOptions {
  prefix?: string
  showTimestamp?: boolean
}

const isDevelopment = process.env.NODE_ENV === 'development'

// Color codes for different log levels (works in browser console)
const LOG_COLORS = {
  debug: 'color: #6b7280', // gray
  info: 'color: #3b82f6',  // blue
  warn: 'color: #f59e0b',  // amber
  error: 'color: #ef4444', // red
} as const

// Emoji prefixes for visual distinction
const LOG_PREFIXES = {
  debug: '🔍',
  info: 'ℹ️',
  warn: '⚠️',
  error: '❌',
} as const

function formatMessage(level: LogLevel, prefix?: string): string {
  const emoji = LOG_PREFIXES[level]
  const levelLabel = level.toUpperCase().padEnd(5)
  const prefixStr = prefix ? `[${prefix}]` : ''
  return `${emoji} ${levelLabel} ${prefixStr}`.trim()
}

function createLogFunction(level: LogLevel, options: LoggerOptions = {}) {
  return (...args: unknown[]) => {
    // Skip debug logs in production
    if (level === 'debug' && !isDevelopment) {
      return
    }

    const formattedMessage = formatMessage(level, options.prefix)
    
    // Add timestamp in development for debugging
    const timestamp = isDevelopment ? new Date().toISOString().split('T')[1].slice(0, 12) : ''
    const fullMessage = timestamp ? `[${timestamp}] ${formattedMessage}` : formattedMessage

    switch (level) {
      case 'debug':
        console.log(fullMessage, ...args)
        break
      case 'info':
        console.info(fullMessage, ...args)
        break
      case 'warn':
        console.warn(fullMessage, ...args)
        break
      case 'error':
        console.error(fullMessage, ...args)
        break
    }
  }
}

/**
 * Main logger instance with standard log methods
 */
export const logger = {
  /**
   * Debug level - only shows in development
   * Use for detailed debugging information
   */
  debug: createLogFunction('debug'),
  
  /**
   * Info level - shows in all environments
   * Use for important operational information
   */
  info: createLogFunction('info'),
  
  /**
   * Warn level - shows in all environments
   * Use for potentially problematic situations
   */
  warn: createLogFunction('warn'),
  
  /**
   * Error level - shows in all environments
   * Use for error conditions
   */
  error: createLogFunction('error'),
}

/**
 * Create a prefixed logger for a specific module
 * Useful for tracking logs from specific parts of the codebase
 * 
 * Usage:
 *   const log = createLogger('RealtimeManager')
 *   log.debug('Initializing presence')
 */
export function createLogger(prefix: string): typeof logger {
  return {
    debug: createLogFunction('debug', { prefix }),
    info: createLogFunction('info', { prefix }),
    warn: createLogFunction('warn', { prefix }),
    error: createLogFunction('error', { prefix }),
  }
}

/**
 * Specialized loggers for different domains
 */
export const realtimeLogger = createLogger('Realtime')
export const apiLogger = createLogger('API')
export const communicationLogger = createLogger('Communication')
export const presenceLogger = createLogger('Presence')

export default logger
