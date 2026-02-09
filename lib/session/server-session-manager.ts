/**
 * Server-Side Session Manager for NextJS with NextAuth
 * Replaces localStorage-based session management with pure NextAuth approach
 * Follows NextJS best practices for server-side session handling
 */

import { getSession, signOut } from 'next-auth/react'

// Extended NextAuth types for our app
interface ExtendedUser {
  id: string
  name?: string | null
  email?: string | null
  image?: string | null
  role?: string
  avatar?: string
  sessionStartTime?: number
  permissions?: any[]
  requiresTwoFactor?: boolean
  twoFactorVerified?: boolean
}

interface ExtendedSession {
  user: ExtendedUser
}

interface ServerSessionData {
  userId: string
  email: string
  name: string
  role: string
  avatar?: string
  sessionStartTime: number
  lastActivity: number
}

export class ServerSessionManager {
  private static readonly SESSION_TIMEOUT = 1 * 60 * 60 * 1000 // 1 hour of inactivity
  private static readonly ACTIVITY_CHECK_INTERVAL = 60 * 1000 // Check every minute
  
  private static activityTimer: NodeJS.Timeout | null = null
  private static lastActivityTime: number = Date.now()

  /**
   * Initialize server-side session monitoring
   */
  static async initialize(): Promise<void> {
    if (typeof window === 'undefined') return

    try {
      // Start activity monitoring without localStorage
      this.startActivityMonitoring()
      console.log('✅ Server session manager initialized')
    } catch (error) {
      console.error('Failed to initialize server session manager:', error)
    }
  }

  /**
   * Start monitoring user activity for session timeout
   */
  private static startActivityMonitoring(): void {
    const activityEvents = [
      'mousedown', 'mousemove', 'keypress', 'scroll',
      'touchstart', 'click', 'focus', 'keydown'
    ]

    // Update activity timestamp on user interaction
    const updateActivity = () => {
      this.lastActivityTime = Date.now()
    }

    // Add activity listeners
    activityEvents.forEach(event => {
      document.addEventListener(event, updateActivity, { passive: true })
    })

    // Start periodic session validation
    this.activityTimer = setInterval(async () => {
      await this.validateSession()
    }, this.ACTIVITY_CHECK_INTERVAL)
  }

  /**
   * Validate current session and handle timeout
   */
  private static async validateSession(): Promise<void> {
    try {
      // Check if user has been inactive too long
      const timeSinceLastActivity = Date.now() - this.lastActivityTime
      
      if (timeSinceLastActivity > this.SESSION_TIMEOUT) {
        console.log('Session timeout due to inactivity')
        await this.handleSessionTimeout()
        return
      }

      // Verify session is still valid with NextAuth
      const session = await getSession()
      if (!session) {
        console.log('Session no longer valid')
        await this.handleSessionExpired()
      }
    } catch (error) {
      console.error('Session validation error:', error)
    }
  }

  /**
   * Handle session timeout due to inactivity
   */
  private static async handleSessionTimeout(): Promise<void> {
    try {
      console.log('Signing out due to session timeout')
      await signOut({
        callbackUrl: '/auth/login?reason=timeout',
        redirect: true
      })
    } catch (error) {
      console.error('Error during timeout signout:', error)
      // Fallback: redirect manually
      window.location.href = '/auth/login?reason=timeout'
    }
  }

  /**
   * Handle expired session
   */
  private static async handleSessionExpired(): Promise<void> {
    try {
      console.log('Session expired - redirecting to login')
      await signOut({
        callbackUrl: '/auth/login?reason=expired',
        redirect: true
      })
    } catch (error) {
      console.error('Error during expired session signout:', error)
      // Fallback: redirect manually
      window.location.href = '/auth/login?reason=expired'
    }
  }

  /**
   * Update user activity timestamp
   */
  static updateActivity(): void {
    this.lastActivityTime = Date.now()
  }

  /**
   * Get current session data from NextAuth
   */
  static async getCurrentSession(): Promise<ServerSessionData | null> {
    try {
      const session = await getSession() as ExtendedSession | null
      
      if (!session?.user) {
        return null
      }

      const user = session.user
      return {
        userId: user.id,
        email: user.email || '',
        name: user.name || '',
        role: user.role || 'user',
        avatar: user.avatar,
        sessionStartTime: user.sessionStartTime || Date.now(),
        lastActivity: this.lastActivityTime
      }
    } catch (error) {
      console.error('Error getting current session:', error)
      return null
    }
  }

  /**
   * Cleanup session manager
   */
  static cleanup(): void {
    if (this.activityTimer) {
      clearInterval(this.activityTimer)
      this.activityTimer = null
    }
    
    // Remove activity listeners
    const activityEvents = [
      'mousedown', 'mousemove', 'keypress', 'scroll',
      'touchstart', 'click', 'focus', 'keydown'
    ]

    activityEvents.forEach(event => {
      document.removeEventListener(event, this.updateActivity)
    })

    console.log('Server session manager cleaned up')
  }

  /**
   * Check if session is about to expire (within 5 minutes)
   */
  static isSessionExpiringSoon(): boolean {
    const timeSinceLastActivity = Date.now() - this.lastActivityTime
    return timeSinceLastActivity > (this.SESSION_TIMEOUT - 5 * 60 * 1000)
  }

  /**
   * Get time remaining before session timeout (in minutes)
   */
  static getTimeUntilTimeout(): number {
    const timeSinceLastActivity = Date.now() - this.lastActivityTime
    const timeRemaining = this.SESSION_TIMEOUT - timeSinceLastActivity
    return Math.max(0, Math.floor(timeRemaining / (60 * 1000)))
  }
}

export default ServerSessionManager