"use client"

import { useState, useEffect, useCallback } from "react"
import { useSession } from "next-auth/react"
import { handleAPIError } from "@/lib/utils/api-client"
import type { UpdateProfileData, ChangePasswordData, ProfileResponse } from "@/lib/validations/profile"

interface UseProfileReturn {
  profileData: ProfileResponse | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  updateProfile: (data: UpdateProfileData) => Promise<{ success: boolean; error?: string }>
  changePassword: (data: ChangePasswordData) => Promise<{ success: boolean; error?: string }>
  sessionDuration: number
  formatDuration: (seconds: number) => string
}

export const useProfile = (): UseProfileReturn => {
  const { data: session, update: updateSession } = useSession()
  const [profileData, setProfileData] = useState<ProfileResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sessionDuration, setSessionDuration] = useState(0)

  // Calculate session duration
  useEffect(() => {
    const sessionUser = session?.user as any
    if (!sessionUser?.sessionStartTime) return

    const calculateDuration = () => {
      const now = Date.now()
      const startTime = sessionUser.sessionStartTime
      const duration = Math.floor((now - startTime) / 1000)
      setSessionDuration(duration)
    }

    // Initial calculation
    calculateDuration()

    // Update every 10 seconds instead of every second to reduce re-renders
    const interval = setInterval(calculateDuration, 10000)

    return () => clearInterval(interval)
  }, [(session?.user as any)?.sessionStartTime])

  // Format duration helper
  const formatDuration = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    const secs = seconds % 60

    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`
    } else {
      return `${secs}s`
    }
  }

  // Fetch profile data
  const refetch = useCallback(async (): Promise<void> => {
    // Prevent multiple simultaneous requests
    if (isLoading) {
      console.log('Profile refetch prevented - already loading')
      return
    }
    
    console.log('Profile refetch started')
    try {
      setIsLoading(true)
      setError(null)

      const response = await fetch('/api/profile')
      const data = await response.json()

      if (data.success) {
        setProfileData(data.data)
      } else {
        setError(data.error || "Failed to fetch profile")
      }
    } catch (err) {
      const errorMessage = "Failed to fetch profile"
      setError(errorMessage)
      handleAPIError(err, errorMessage)
    } finally {
      setIsLoading(false)
    }
  }, [isLoading])

  // Update profile
  const updateProfile = useCallback(async (updateData: UpdateProfileData): Promise<{ success: boolean; error?: string }> => {
    try {
      setIsLoading(true)
      setError(null)

      const response = await fetch('/api/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(updateData),
      })

      const result = await response.json()

      if (result.success) {
        // Update local state
        setProfileData(prev => prev ? { ...prev, ...result.data } : null)
        
        // Update session if name or avatar changed
        const sessionUser = session?.user as any
        if (updateData.name !== sessionUser?.name || updateData.avatar !== sessionUser?.avatar) {
          await updateSession({
            ...session,
            user: {
              ...sessionUser,
              name: updateData.name || sessionUser?.name,
              avatar: updateData.avatar || sessionUser?.avatar,
            }
          })
        }

        return { success: true }
      } else {
        setError(result.error || "Failed to update profile")
        return { success: false, error: result.error || "Failed to update profile" }
      }
    } catch (err) {
      const errorMsg = "Failed to update profile"
      setError(errorMsg)
      handleAPIError(err, errorMsg)
      return { success: false, error: errorMsg }
    } finally {
      setIsLoading(false)
    }
  }, [session, updateSession])

  // Change password
  const changePassword = useCallback(async (passwordData: ChangePasswordData): Promise<{ success: boolean; error?: string }> => {
    try {
      setIsLoading(true)
      setError(null)

      const response = await fetch('/api/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(passwordData),
      })

      const result = await response.json()

      if (result.success) {
        return { success: true }
      } else {
        setError(result.error || "Failed to change password")
        return { success: false, error: result.error || "Failed to change password" }
      }
    } catch (err) {
      const errorMsg = "Failed to change password"
      setError(errorMsg)
      handleAPIError(err, errorMsg)
      return { success: false, error: errorMsg }
    } finally {
      setIsLoading(false)
    }
  }, [])

  return {
    profileData,
    isLoading,
    error,
    refetch,
    updateProfile,
    changePassword,
    sessionDuration,
    formatDuration,
  }
}