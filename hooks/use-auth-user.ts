import { useSession, signOut } from 'next-auth/react'
import { useCallback } from 'react'

interface AuthUser {
  id: string
  name: string
  email: string
  role: string
  roleDisplayName?: string
  department?: string
  avatar?: string
  image?: string
  permissions?: any[]
  requiresTwoFactor?: boolean
  twoFactorVerified?: boolean
  sessionStartTime?: number
  iat?: number
}

interface UseAuthUserReturn {
  user: AuthUser | null
  loading: boolean
  status: 'loading' | 'authenticated' | 'unauthenticated'
  updateUser: (userData: Partial<AuthUser>) => Promise<void>
  signOut: () => Promise<void>
  refreshSession: () => Promise<void>
}

export function useAuthUser(): UseAuthUserReturn {
  const { data: session, status, update } = useSession()

  // Extract user from session - this is the single source of truth
  const user = session?.user ? (session.user as AuthUser) : null
  const loading = status === 'loading'

  // Update user data via NextAuth session update
  const updateUser = useCallback(async (userData: Partial<AuthUser>) => {
    try {
      console.log('Updating user session with:', userData)
      await update({
        user: { ...user, ...userData },
        ...userData // Also spread at top level for specific fields like avatar, twoFactorVerified
      })
      console.log('User session updated successfully')
    } catch (error) {
      console.error('Error updating user session:', error)
      throw error
    }
  }, [update, user])

  // Sign out wrapper
  const handleSignOut = useCallback(async () => {
    try {
      console.log('Signing out user')
      await signOut({
        callbackUrl: '/auth/login',
        redirect: true
      })
    } catch (error) {
      console.error('Error during sign out:', error)
      throw error
    }
  }, [])

  // Refresh session data from server
  const refreshSession = useCallback(async () => {
    try {
      console.log('Refreshing session from server')
      await update()
      console.log('Session refreshed successfully')
    } catch (error) {
      console.error('Error refreshing session:', error)
      throw error
    }
  }, [update])

  return {
    user,
    loading,
    status,
    updateUser,
    signOut: handleSignOut,
    refreshSession,
  }
}