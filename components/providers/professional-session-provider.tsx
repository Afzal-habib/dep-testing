"use client"

import { createContext, useContext, useEffect, useState, useCallback, ReactNode, memo, useMemo } from 'react'
import { useSession, signOut } from 'next-auth/react'
import { useDispatch } from 'react-redux'
import { setAuth, clearAuth } from '@/store/slices/authSlice'
import { ServerSessionManager } from '@/lib/session/server-session-manager'
import { useRouter } from 'next/navigation'

interface ProfessionalSessionContextType {
  isLoading: boolean
  isAuthenticated: boolean
  user: any
  timeUntilExpiry: number
  extendSession: () => void
  logout: () => Promise<void>
}

const ProfessionalSessionContext = createContext<ProfessionalSessionContextType | undefined>(undefined)

interface ProfessionalSessionProviderProps {
  children: ReactNode
}

// Memoized Professional Session Provider for better performance
function ProfessionalSessionProviderComponent({ children }: ProfessionalSessionProviderProps) {
  const { data: session, status } = useSession()
  const dispatch = useDispatch()
  const router = useRouter()
  const [timeUntilExpiry, setTimeUntilExpiry] = useState(0)
  const [isInitialized, setIsInitialized] = useState(false)

  // Memoize computed values to prevent unnecessary re-renders
  const { isLoading, isAuthenticated } = useMemo(() => ({
    isLoading: status === 'loading',
    isAuthenticated: !!session?.user && status === 'authenticated'
  }), [status, session?.user])

  /**
   * Handle user logout
   */
  const logout = useCallback(async () => {
    try {
      // Clean up session manager
      ServerSessionManager.cleanup()
      
      // Clear Redux state
      dispatch(clearAuth())
      
      // Use NextAuth signOut
      await signOut({ 
        callbackUrl: '/auth/login',
        redirect: false 
      })
      
      // Force navigation
      router.push('/auth/login')
    } catch (error) {
      console.error('Logout error:', error)
      // Force redirect as fallback
      window.location.href = '/auth/login'
    }
  }, [dispatch, router])

  /**
   * Extend session by updating activity
   */
  const extendSession = useCallback(() => {
    if (isAuthenticated) {
      ServerSessionManager.updateActivity()
    }
  }, [isAuthenticated])

  /**
   * Initialize session when user logs in
   */
  useEffect(() => {
    if (status === 'loading') return

    if (session?.user) {
      const sessionData = {
        userId: (session.user as any).id || '',
        email: session.user.email || '',
        name: session.user.name || '',
        role: (session.user as any).role || '',
        avatar: (session.user as any).avatar || '',
        lastActivity: Date.now(),
        sessionStart: Date.now()
      }

      // Initialize server session manager
      ServerSessionManager.initialize()

      // Update Redux store
      dispatch(setAuth({
        id: sessionData.userId,
        name: sessionData.name,
        email: sessionData.email,
        role: sessionData.role,
        avatar: sessionData.avatar
      }))

      setIsInitialized(true)
    } else if (status === 'unauthenticated') {
      // Clean up server session manager
      ServerSessionManager.cleanup()
      dispatch(clearAuth())
      setIsInitialized(true)
    }
  }, [session, status, dispatch])

  /**
   * Cross-tab synchronization is now handled automatically by NextAuth
   */
  useEffect(() => {
    // NextAuth handles cross-tab sync automatically via JWT tokens
    // No manual setup needed for cross-tab communication
    
    return () => {
      // Cleanup on unmount
      if (status !== 'authenticated') {
        ServerSessionManager.cleanup()
      }
    }
  }, [status])

  /**
   * OPTIMIZED: Update time until expiry - less frequent checks for better performance
   */
  useEffect(() => {
    if (!isAuthenticated) {
      setTimeUntilExpiry(0)
      return
    }

    const updateTimer = () => {
      const timeRemaining = ServerSessionManager.getTimeUntilTimeout()
      setTimeUntilExpiry(timeRemaining)
      
      // Auto-logout if session expires soon
      if (timeRemaining <= 0) {
        logout()
      }
    }

    // Update immediately
    updateTimer()

    // OPTIMIZED: Update every 2 minutes instead of 1 minute for better performance
    const interval = setInterval(updateTimer, 120000)

    return () => clearInterval(interval)
  }, [isAuthenticated, logout])

  /**
   * Handle page visibility for activity tracking
   */
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden && isAuthenticated) {
        extendSession()
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange)
  }, [isAuthenticated, extendSession])

  // Memoize the context value to prevent unnecessary re-renders
  const value = useMemo((): ProfessionalSessionContextType => ({
    isLoading,
    isAuthenticated,
    user: session?.user || null,
    timeUntilExpiry,
    extendSession,
    logout
  }), [isLoading, isAuthenticated, session?.user, timeUntilExpiry, extendSession, logout])

  return (
    <ProfessionalSessionContext.Provider value={value}>
      {children}
    </ProfessionalSessionContext.Provider>
  )
}

// Export memoized version for better performance
export const ProfessionalSessionProvider = memo(ProfessionalSessionProviderComponent)

export function useProfessionalSession() {
  const context = useContext(ProfessionalSessionContext)
  if (context === undefined) {
    throw new Error('useProfessionalSession must be used within a ProfessionalSessionProvider')
  }
  return context
}

export default ProfessionalSessionProvider