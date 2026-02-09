"use client"

import { SessionProvider } from 'next-auth/react'
import { useEffect } from 'react'
import { usePathname } from 'next/navigation'

interface ServerSessionProviderProps {
  children: React.ReactNode
  session?: any
}

/**
 * Enhanced session provider that relies entirely on server-side session management
 * without any localStorage dependencies, following Next.js best practices
 */
export function ServerSessionProvider({ 
  children, 
  session 
}: ServerSessionProviderProps) {
  const pathname = usePathname()

  // Clean up any existing localStorage on mount (migration cleanup)
  useEffect(() => {
    const cleanupLegacyStorage = () => {
      if (typeof window === 'undefined') return
      
      try {
        // Remove old localStorage keys if they exist
        const legacyKeys = [
          'logged_in_user',
          'userPermissions', 
          'user_permissions',
          'user_role',
          'user_department',
          'session_data',
          'last_activity'
        ]
        
        legacyKeys.forEach(key => {
          if (localStorage.getItem(key)) {
            localStorage.removeItem(key)
            console.log(`Cleaned up legacy storage key: ${key}`)
          }
        })

        // Clean up any keys that start with our app prefixes
        const keysToRemove = Object.keys(localStorage).filter(key => 
          key.startsWith('crm_') || 
          key.startsWith('auth_') ||
          key.startsWith('user_')
        )
        
        keysToRemove.forEach(key => {
          localStorage.removeItem(key)
          console.log(`Cleaned up legacy storage key: ${key}`)
        })

        if (legacyKeys.length > 0 || keysToRemove.length > 0) {
          console.log('✅ Completed migration from localStorage to server-side sessions')
        }
      } catch (error) {
        console.warn('Failed to clean up legacy localStorage:', error)
      }
    }

    // Only run cleanup once
    const hasCleanedUp = sessionStorage.getItem('legacy_cleanup_done')
    if (!hasCleanedUp) {
      cleanupLegacyStorage()
      sessionStorage.setItem('legacy_cleanup_done', 'true')
    }
  }, [])

  return (
    <SessionProvider 
      session={session}
      // Reduce session polling for better performance since we're server-side focused
      refetchInterval={5 * 60} // 5 minutes
      refetchOnWindowFocus={true}
      refetchWhenOffline={false}
    >
      {children}
    </SessionProvider>
  )
}

export default ServerSessionProvider