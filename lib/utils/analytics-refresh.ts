/**
 * Analytics Refresh Utility
 * Centralized solution for triggering analytics refresh after CRUD operations
 */

import { QueryClient } from '@tanstack/react-query'

interface AnalyticsRefreshConfig {
  projectId: string
  queryClient: QueryClient
  delay?: number
}

/**
 * Trigger analytics refresh for a specific project
 * This completely removes the cache and forces a fresh fetch
 */
export async function refreshAnalytics({ projectId, queryClient, delay = 2000 }: AnalyticsRefreshConfig) {
  // Ensure projectId is a string (handle cases where object is passed)
  const cleanProjectId = typeof projectId === 'string' ? projectId : (projectId as any)?._id || String(projectId)
  
  // Log with stack trace to identify caller
  console.log('🔄 [ANALYTICS-UTIL] Scheduling refresh for project:', cleanProjectId, 'in', delay, 'ms')
  console.log('📍 [ANALYTICS-UTIL] Called from:', new Error().stack?.split('\n')[2]?.trim())
  
  try {
    // FIRST: Remove cache immediately to prevent stale data
    console.log('🗑️ [ANALYTICS-UTIL] Removing all analytics cache immediately...')
    
    queryClient.removeQueries({ 
      queryKey: ['project-analytics'],
      exact: false 
    })
    queryClient.removeQueries({ 
      queryKey: ['analytics'],
      exact: false 
    })
    
    // THEN: Wait for MongoDB to process the changes
    console.log(`⏳ [ANALYTICS-UTIL] Waiting ${delay}ms for database to process changes...`)
    await new Promise(r => setTimeout(r, delay))
    
    // FINALLY: Invalidate to trigger fresh fetch
    console.log('🔄 [ANALYTICS-UTIL] Invalidating analytics queries to trigger fresh fetch...')
    
    await queryClient.invalidateQueries({ 
      queryKey: ['project-analytics', cleanProjectId],
      refetchType: 'active'
    })
    
    console.log('✅ [ANALYTICS-UTIL] Analytics refresh completed successfully')
  } catch (error) {
    console.error('❌ [ANALYTICS-UTIL] Error refreshing analytics:', error)
  }
}

/**
 * Trigger immediate analytics refresh (no delay)
 */
export async function refreshAnalyticsImmediate({ projectId, queryClient }: Omit<AnalyticsRefreshConfig, 'delay'>) {
  return refreshAnalytics({ projectId, queryClient, delay: 0 })
}
