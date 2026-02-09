/**
 * Middleware Logging and Monitoring Utility
 * Provides comprehensive logging for API endpoint protection
 */

import { NextRequest } from "next/server"

export interface MiddlewareLogData {
  url: string
  method: string
  resource: string
  action: string
  userEmail?: string
  userId?: string
  ip: string
  userAgent: string
  rateLimitType?: string
  duration: number
  timestamp: string
  success: boolean
  errorType?: 'rate_limit' | 'authentication' | 'authorization' | 'validation' | 'server_error'
  errorMessage?: string
  statusCode?: number
}

export class MiddlewareLogger {
  private static logs: MiddlewareLogData[] = []
  private static readonly MAX_LOGS = 1000 // Keep last 1000 logs in memory

  /**
   * Log a middleware event
   */
  static log(data: MiddlewareLogData): void {
    const logEntry: MiddlewareLogData = {
      ...data,
      ip: data.ip || 'unknown',
      userAgent: data.userAgent || 'unknown',
      timestamp: data.timestamp || new Date().toISOString()
    }

    // Add to in-memory logs
    this.logs.push(logEntry)

    // Keep only the last MAX_LOGS entries
    if (this.logs.length > this.MAX_LOGS) {
      this.logs.shift()
    }

    // Console logging based on success/failure
    if (data.success) {
      console.log('✅ API Access:', {
        method: data.method,
        resource: data.resource,
        action: data.action,
        user: data.userEmail || 'anonymous',
        duration: `${data.duration}ms`
      })
    } else {
      console.warn('🚫 API Access Denied:', {
        method: data.method,
        resource: data.resource,
        action: data.action,
        error: data.errorType,
        message: data.errorMessage,
        duration: `${data.duration}ms`
      })
    }

    // In production, you would send this to your monitoring service
    if (process.env.NODE_ENV === 'production') {
      // Example: Send to monitoring service
      // await sendToMonitoringService(logEntry)
    }
  }

  /**
   * Extract request info for logging
   */
  static extractRequestInfo(request: NextRequest): {
    ip: string
    userAgent: string
    url: string
    method: string
  } {
    return {
      ip: request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
          request.headers.get('x-real-ip') ||
          'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
      url: request.url,
      method: request.method
    }
  }

  /**
   * Get recent logs for monitoring dashboard
   */
  static getRecentLogs(limit = 100): MiddlewareLogData[] {
    return this.logs.slice(-limit).reverse() // Most recent first
  }

  /**
   * Get security statistics
   */
  static getSecurityStats(): {
    totalRequests: number
    successfulRequests: number
    blockedRequests: number
    rateLimitBlocks: number
    authFailures: number
    permissionDenials: number
    topResources: Array<{ resource: string; count: number }>
    topUsers: Array<{ userEmail: string; count: number }>
  } {
    const total = this.logs.length
    const successful = this.logs.filter(log => log.success).length
    const blocked = total - successful
    const rateLimitBlocks = this.logs.filter(log => log.errorType === 'rate_limit').length
    const authFailures = this.logs.filter(log => log.errorType === 'authentication').length
    const permissionDenials = this.logs.filter(log => log.errorType === 'authorization').length

    // Count resources
    const resourceCounts: Record<string, number> = {}
    const userCounts: Record<string, number> = {}

    this.logs.forEach(log => {
      // Count resources
      resourceCounts[log.resource] = (resourceCounts[log.resource] || 0) + 1
      
      // Count users (exclude anonymous)
      if (log.userEmail && log.userEmail !== 'anonymous') {
        userCounts[log.userEmail] = (userCounts[log.userEmail] || 0) + 1
      }
    })

    const topResources = Object.entries(resourceCounts)
      .map(([resource, count]) => ({ resource, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)

    const topUsers = Object.entries(userCounts)
      .map(([userEmail, count]) => ({ userEmail, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)

    return {
      totalRequests: total,
      successfulRequests: successful,
      blockedRequests: blocked,
      rateLimitBlocks,
      authFailures,
      permissionDenials,
      topResources,
      topUsers
    }
  }

  /**
   * Clear logs (useful for testing or periodic cleanup)
   */
  static clearLogs(): void {
    this.logs = []
    console.log('🧹 Middleware logs cleared')
  }

  /**
   * Export logs for analysis
   */
  static exportLogs(): MiddlewareLogData[] {
    return [...this.logs] // Return a copy
  }
}

/**
 * Helper function to create middleware log data from request and results
 */
export function createLogData(
  request: NextRequest,
  resource: string,
  action: string,
  startTime: number,
  success: boolean,
  options: {
    userEmail?: string
    userId?: string
    rateLimitType?: string
    errorType?: MiddlewareLogData['errorType']
    errorMessage?: string
    statusCode?: number
  } = {}
): MiddlewareLogData {
  const requestInfo = MiddlewareLogger.extractRequestInfo(request)
  
  return {
    ...requestInfo,
    resource,
    action,
    duration: Date.now() - startTime,
    success,
    timestamp: new Date().toISOString(),
    ip: requestInfo.ip,
    userAgent: requestInfo.userAgent,
    ...options
  }
}