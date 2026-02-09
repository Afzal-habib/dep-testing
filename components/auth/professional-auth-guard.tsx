"use client"

import type React from "react"
import { useRouter } from "next/navigation"
import { useEffect, useState, useCallback, useMemo } from "react"
import { ProfessionalLoader } from "../shared/professional-loader"
import { useProfessionalSession } from "../providers/professional-session-provider"

interface ProfessionalAuthGuardProps {
  children: React.ReactNode
  requiredRole?: string[]
}

// Cache for role checks to avoid repeated validations
const roleCheckCache = new Map<string, boolean>()

export function ProfessionalAuthGuard({ children, requiredRole }: ProfessionalAuthGuardProps) {
  const { isLoading, isAuthenticated, user } = useProfessionalSession()
  const router = useRouter()
  const [isChecking, setIsChecking] = useState(false) // Start false for instant render

  // Memoize role validation to prevent unnecessary recalculations
  const hasRequiredRole = useMemo(() => {
    if (!requiredRole || requiredRole.length === 0) return true
    if (!user) return false
    
    const userRole = (user as any)?.role
    const cacheKey = `${userRole}:${requiredRole.join(',')}`
    
    // Check cache first
    if (roleCheckCache.has(cacheKey)) {
      return roleCheckCache.get(cacheKey)
    }
    
    const hasRole = userRole && requiredRole.includes(userRole)
    
    // Cache the result
    roleCheckCache.set(cacheKey, hasRole)
    
    // Clean cache if it gets too large
    if (roleCheckCache.size > 50) {
      const iterator = roleCheckCache.keys()
      const firstKey = iterator.next().value
      if (firstKey) {
        roleCheckCache.delete(firstKey)
      }
    }
    
    return hasRole
  }, [user, requiredRole])

  // Optimized authentication check - non-blocking
  const handleAuthCheck = useCallback(() => {
    // Don't process if still loading
    if (isLoading) return

    // Use queueMicrotask to defer redirect and prevent blocking
    queueMicrotask(() => {
      // Check authentication - immediate redirect
      if (!isAuthenticated) {
        router.replace("/auth/login")
        return
      }

      // Check role requirements
      if (!hasRequiredRole) {
        router.replace("/unauthorized")
        return
      }
    })
  }, [isLoading, isAuthenticated, hasRequiredRole, router])

  useEffect(() => {
    handleAuthCheck()
  }, [handleAuthCheck])

  // Show minimal loading for better perceived performance
  if (isLoading) {
    return (
      <div className="fixed inset-0 bg-background flex items-center justify-center z-50">
        <ProfessionalLoader size="md" />
      </div>
    )
  }

  // Early return for unauthenticated users
  if (!isAuthenticated) {
    return null
  }

  // Early return for unauthorized users
  if (!hasRequiredRole) {
    return null
  }

  // Render children immediately for authorized users
  return <>{children}</>
}

export default ProfessionalAuthGuard