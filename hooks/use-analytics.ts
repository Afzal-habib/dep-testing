import { useCallback, useMemo, useEffect } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setAnalyticsData,
  setAnalyticsInsights,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  clearFilters,
  setSort,
  setPagination,
  setRefreshInterval,
  setLastUpdated,
  resetState,
  invalidateCache,
  setDateRangePreset,
  setCustomDateRange,
  selectIsDataStale,
} from '@/store/slices/analyticsSlice'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiRequest } from '@/lib/utils/api-client'
import { useProject } from './use-projects'

// Comprehensive Analytics Type Definitions
export interface AnalyticsOverview {
  totalTasks?: number
  completedTasks?: number
  overdueTasks?: number
  totalTeamMembers?: number
  totalProjects?: number
  activeProjects?: number
  completedProjects?: number
  onHoldProjects?: number
  averageProgress?: number
  totalBudget?: number
  totalSpent?: number
  budget?: {
    allocated: number
    spent: number
    remaining: number
  }
  timeline?: {
    totalDays: number
    daysPassed: number
    daysRemaining: number
    isOnTrack: boolean
  }
}

export interface AnalyticsTasks {
  _id?: null | string
  totalTasks: number
  completedTasks: number
  inProgressTasks: number
  pendingTasks: number
  overdueTasks: number
}

export interface AnalyticsKPI {
  taskCompletion: number
  budgetUtilization: number
  teamProductivity: number
  timelineHealth: number
  overallHealth: number
}

export interface DepartmentAnalytics {
  id: string
  name: string
  totalTasks: number
  completedTasks: number
  overdueTasks: number
  completionRate: number
  productivity: number
  avgCompletionTime: number
  teamMembers: number
  efficiency: number
}

export interface IndividualAnalytics {
  id: string
  name: string
  email: string
  avatar?: string
  role: string
  department: string
  totalTasks: number
  completedTasks: number
  overdueTasks: number
  completionRate: number
  productivity: number
  efficiency: number
}

export interface AnalyticsTeam {
  departments: DepartmentAnalytics[]
  individuals: IndividualAnalytics[]
  summary: {
    totalDepartments: number
    totalTeamMembers: number
    avgDepartmentProductivity: number
    avgIndividualProductivity: number
  }
}


export interface AnalyticsResources {
  budget: {
    total: number
    allocated?: number
    actualCosts?: number
    utilization: number
    variance?: number
    breakdown?: Record<string, number>
  }
  hours: {
    totalEstimated?: number
    totalActual?: number
    completedEstimated?: number
    completedActual?: number
    efficiency: number
    variance?: number
  }
  utilization?: {
    assignedTasks: number
    unassignedTasks: number
    utilizationRate: number
    totalTasks: number
  }
  summary: {
    overallEfficiency: number
    budgetHealth?: string
    resourceHealth?: string
  }
}

export interface AnalyticsCollaboration {
  departmentCollaboration: number
  crossDepartmentTasks: number
  communicationScore: number
}

export interface AnalyticsPerformance {
  completionRate: number
  averageTaskDuration: number
  productivityScore: number
  qualityScore: number
}

export interface AnalyticsTrends {
  tasksCompleted: Array<{ date: string; completed: number; created: number }>
  teamEfficiency: Array<{ member: string; efficiency: number; tasks: number }>
}


export interface AnalyticsRisk {
  id: string
  type: string
  level: string
  description: string
  impact: string
  mitigation: string
  probability?: string
  affectedAreas?: string[]
}

export interface AnalyticsInsight {
  type: string
  category?: string
  title?: string
  description?: string
  recommendation: string
  priority?: string
  message?: string
  actionable?: boolean
}

export interface AnalyticsMeta {
  dateRange: string
  startDate: string
  endDate: string
  projectId: string
  generatedAt: string
  userId: string
  analyticsVersion: string
}

export interface AnalyticsFilters {
  projectId?: string
  dateRange?: '7d' | '30d' | '90d' | '1y' | 'custom'
  startDate?: Date
  endDate?: Date
  includeCompleted?: boolean
  departmentId?: string
  userId?: string
  taskStatus?: string[]
}

export interface AnalyticsSort {
  field: string
  direction: 'asc' | 'desc'
}

export interface AnalyticsPagination {
  page: number
  limit: number
  total: number
  totalPages: number
}

export interface EnhancedAnalyticsData {
  overview: AnalyticsOverview
  tasks: AnalyticsTasks
  kpi: AnalyticsKPI
  team: AnalyticsTeam
  resources: AnalyticsResources
  collaboration: AnalyticsCollaboration
  performance: AnalyticsPerformance
  trends: AnalyticsTrends
  risks: AnalyticsRisk[]
  insights: AnalyticsInsight[]
  meta?: AnalyticsMeta
}

// API Response interface to match the actual response structure
export interface ApiAnalyticsResponse {
  success: boolean
  data: EnhancedAnalyticsData
  message: string
}

export function useAnalytics() {
  const dispatch = useAppDispatch()

  const {
    data,
    insights,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    lastUpdated,
    refreshInterval,
  } = useAppSelector((state) => state.analytics)

  // Memoize query params to prevent unnecessary re-renders
  const queryParams = useMemo(() => {
    const params = new URLSearchParams()
    
    if (filters.projectId) params.append('projectId', filters.projectId)
    if (filters.dateRange) params.append('dateRange', filters.dateRange)
    if (filters.startDate) params.append('startDate', filters.startDate.toISOString())
    if (filters.endDate) params.append('endDate', filters.endDate.toISOString())
    if (filters.includeCompleted !== undefined) params.append('includeCompleted', filters.includeCompleted.toString())
    if (filters.departmentId) params.append('departmentId', filters.departmentId)
    if (filters.userId) params.append('userId', filters.userId)
    if (filters.taskStatus?.length) params.append('taskStatus', filters.taskStatus.join(','))
    
    return params.toString()
  }, [filters])

  // Check if data is stale
  const isDataStale = useMemo(() => 
    selectIsDataStale(lastUpdated, refreshInterval), 
    [lastUpdated, refreshInterval]
  )

  // Use TanStack Query directly for analytics data
  const { data: fetchedData, isLoading: queryLoading, error: queryError, refetch: refetchAnalytics } = useQuery({
    queryKey: ['analytics', queryParams],
    queryFn: async () => {
      dispatch(setLoading(true))
      try {
        const url = `/api/analytics${queryParams ? `?${queryParams}` : ''}`
        const response = await apiRequest(url) as any
        console.log('Fetched analytics response242', response)
        
        // Transform API response to match expected interface
        let analyticsData: EnhancedAnalyticsData
        
        // Handle different response formats
        if (response?.success && response?.data) {
          // API returns {success: true, data: {...}}
          analyticsData = response.data
        } else if (response?.data) {
          // API returns direct data object
          analyticsData = response.data
        } else if (response) {
          // API returns data directly
          analyticsData = response
        } else {
          throw new Error('No analytics data received')
        }
        
        dispatch(setAnalyticsData(analyticsData))
        dispatch(setLastUpdated(new Date()))
        return analyticsData
      } catch (error: any) {
        dispatch(setError(error.message || 'Failed to fetch analytics'))
        throw error
      } finally {
        dispatch(setLoading(false))
      }
    },
    staleTime: Math.min(refreshInterval, 60 * 1000), // Max 1 minute stale time
    gcTime: Math.min(refreshInterval * 2, 2 * 60 * 1000), // Max 2 minutes cache
    enabled: true,
    refetchOnMount: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: true,
  })

  // Analytics operations following Department pattern
  const handleFetchAnalytics = useCallback((params: Partial<AnalyticsFilters> = {}) => {
    if (Object.keys(params).length > 0) {
      dispatch(setFilters(params))
    }
    return refetchAnalytics()
  }, [dispatch, refetchAnalytics])

  const handleRefreshAnalytics = useCallback(() => {
    dispatch(invalidateCache())
    return refetchAnalytics()
  }, [dispatch, refetchAnalytics])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<AnalyticsFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleClearFilters = useCallback(() => {
    dispatch(clearFilters())
  }, [dispatch])

  const handleSetSort = useCallback((newSort: any) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: any) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  // Date range helpers
  const handleSetDateRange = useCallback((range: '7d' | '30d' | '90d' | '1y') => {
    dispatch(setDateRangePreset(range))
  }, [dispatch])

  const handleSetCustomDateRange = useCallback((startDate: Date, endDate: Date) => {
    dispatch(setCustomDateRange({ startDate, endDate }))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetState = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const handleSetRefreshInterval = useCallback((interval: number) => {
    dispatch(setRefreshInterval(interval))
  }, [dispatch])

  // Analytics insights generation
  const generateInsights = useCallback((analyticsData: any): AnalyticsInsight[] => {
    const insights: AnalyticsInsight[] = []
    
    // Safely access nested properties with fallbacks
    const overview = analyticsData?.overview || {}
    const performance = analyticsData?.performance || {}
    const risks = analyticsData?.risks || []

    // Project completion insights based on task completion rate
    const completionRate = performance.completionRate || 0
    if (completionRate > 90) {
      insights.push({
        type: 'success',
        title: 'Excellent Progress',
        description: `${completionRate}% of tasks completed`,
        recommendation: 'Continue current progress',
        priority: 'low'
      })
    } else if (completionRate < 50) {
      insights.push({
        type: 'warning',
        title: 'Low Completion Rate',
        description: `Only ${completionRate}% of tasks completed`,
        recommendation: 'Review task workflows and identify bottlenecks',
        priority: 'high'
      })
    }

    // Task progress insights
    const totalTasks = overview.totalTasks || 0
    const completedTasks = overview.completedTasks || 0
    const overdueTasks = overview.overdueTasks || 0
    
    if (overdueTasks > 0) {
      const overduePercentage = totalTasks > 0 ? Math.round((overdueTasks / totalTasks) * 100) : 0
      insights.push({
        type: 'error',
        title: 'Overdue Tasks',
        description: `${overdueTasks} tasks are overdue (${overduePercentage}% of total)`,
        recommendation: 'Prioritize overdue tasks and reassign resources if needed',
        priority: 'high'
      })
    }

    // Budget insights
    const budget = overview.budget || {}
    const allocated = budget.allocated || 0
    const spent = budget.spent || 0
    
    if (allocated > 0 && spent > 0) {
      const budgetUtilization = Math.round((spent / allocated) * 100)
      if (budgetUtilization > 100) {
        insights.push({
          type: 'error',
          title: 'Budget Overrun',
          description: `Budget is ${budgetUtilization - 100}% over allocated amount`,
          recommendation: 'Review spending and implement cost controls',
          priority: 'high'
        })
      } else if (budgetUtilization > 90) {
        insights.push({
          type: 'warning',
          title: 'Budget Alert',
          description: `${budgetUtilization}% of budget utilized`,
          recommendation: 'Monitor spending closely',
          priority: 'medium'
        })
      }
    }

    // Team productivity insights
    const teamMembers = overview.totalTeamMembers || 0
    if (teamMembers > 0 && completedTasks > 0) {
      const tasksPerMember = (completedTasks / teamMembers).toFixed(1)
      if (parseFloat(tasksPerMember) > 5) {
        insights.push({
          type: 'success',
          title: 'High Productivity',
          message: `Team is completing ${tasksPerMember} tasks per member`,
          recommendation: 'Maintain current productivity levels and recognize high performers',
          priority: 'low'
        })
      } else if (parseFloat(tasksPerMember) < 2) {
        insights.push({
          type: 'info',
          title: 'Low Productivity',
          message: `Only ${tasksPerMember} tasks completed per team member`,
          priority: 'medium',
          actionable: true,
          recommendation: 'Analyze workload distribution and team capacity'
        })
      }
    }


    // Risk-based insights
    const highRisks = risks.filter((r: any) => r.level === 'high' || r.level === 'critical')
    if (highRisks.length > 0) {
      insights.push({
        type: 'error',
        title: 'High Risk Alert',
        message: `${highRisks.length} high-priority risks identified`,
        priority: 'high',
        actionable: true,
        recommendation: 'Review risk mitigation strategies immediately'
      })
    }

    return insights.sort((a, b) => {
      const priorityOrder = { high: 3, medium: 2, low: 1 }
      return priorityOrder[b.priority as keyof typeof priorityOrder] - priorityOrder[a.priority as keyof typeof priorityOrder]
    })
  }, [])

  // Update insights when data changes
  useMemo(() => {
    if (fetchedData || data) {
      const analyticsData = fetchedData || data
      if (analyticsData && !Array.isArray(analyticsData)) {
        const newInsights = generateInsights(analyticsData as EnhancedAnalyticsData)
        dispatch(setAnalyticsInsights(newInsights))
      }
    }
  }, [fetchedData, data, generateInsights, dispatch])

  // Computed values
  const hasData = !!(fetchedData || data)
  const currentData = fetchedData || data
  
  return {
    // State
    analytics: currentData,
    insights,
    loading: queryLoading || loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    lastUpdated,
    refreshInterval,
    isDataStale,

    // Computed values
    hasData,

    // Analytics operations
    fetchAnalytics: handleFetchAnalytics,
    refreshAnalytics: handleRefreshAnalytics,

    // Filter and sort operations
    setFilters: handleSetFilters,
    clearFilters: handleClearFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,

    // Date range operations
    setDateRange: handleSetDateRange,
    setCustomDateRange: handleSetCustomDateRange,

    // Utility operations
    clearError: handleClearError,
    resetState: handleResetState,
    setRefreshInterval: handleSetRefreshInterval,
    refetch: refetchAnalytics,
  }
}

// Project-specific analytics hook
export function useProjectAnalytics(
  projectId: string, 
  dateRange: '7d' | '30d' | '90d' | '1y' = '30d',
  filters: Record<string, any> = {}
): {
  analytics: EnhancedAnalyticsData | null
  insights: AnalyticsInsight[]
  loading: boolean
  error: string | null
  refetch: () => Promise<any>
} {
  const queryKey = ['project-analytics', projectId, dateRange, filters]
  
  const queryClient = useQueryClient()
  
  const {
    data: rawAnalytics,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey,
    queryFn: async () => {
      if (!projectId) {
        throw new Error('Project ID is required')
      }
      
      const params = new URLSearchParams({
        projectId,
        dateRange,
        includeCompleted: 'true',
        // Add timestamp to bypass cache
        _t: Date.now().toString(),
        // Add filters
        ...Object.fromEntries(
          Object.entries(filters).map(([key, value]) => [key, String(value)])
        )
      })
      
      console.log('Fetching analytics for project:', projectId, 'at', new Date().toISOString())
      // Use fetch directly with no-cache headers instead of apiRequest
      const response = await fetch(`/api/analytics?${params.toString()}`, {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      })
      if (!response.ok) {
        throw new Error('Failed to fetch analytics')
      }
      const data = await response.json()
      console.log('Analytics API Response received at', new Date().toISOString())
      return data
    },
    enabled: !!projectId,
    staleTime: 0, // Always consider stale
    gcTime: 0, // Don't cache at all
    refetchOnWindowFocus: false,
    refetchOnMount: true,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      // Retry up to 2 times for network errors, but not for data validation errors
      if (failureCount >= 2) return false
      return !error.message?.includes('Project ID is required')
    },
  })
  
  // Set up listeners for related data changes
  useEffect(() => {
    if (!projectId) return
    
    const handleDataChange = () => {
      // Invalidate and refetch analytics when related data changes
      queryClient.invalidateQueries({ 
        queryKey: ['project-analytics', projectId],
        exact: false 
      })
      
      // Also refetch immediately
      setTimeout(() => {
        refetch()
      }, 500) // Small delay to ensure backend data is updated
    }
    
    // Listen to related query changes
    const unsubscribe = queryClient.getQueryCache().subscribe((event) => {
      if (event.type === 'updated' && event.query.state.data) {
        const queryKey = event.query.queryKey
        const isRelatedQuery = 
          (queryKey[0] === 'tasks' && queryKey[1]?.filters?.projectId === projectId) ||
          (queryKey[0] === 'projects' && queryKey[1] === projectId)
          
        if (isRelatedQuery) {
          handleDataChange()
        }
      }
    })
    
    return unsubscribe
  }, [projectId, queryClient, refetch])

  // Also fetch project data to get team member information
  const { project: selectedProject } = useProject(projectId)
  
  // Transform the API response to match EnhancedAnalyticsData interface
  const analytics: EnhancedAnalyticsData | null = useMemo(() => {
    if (!rawAnalytics) return null
    
    // Handle different response structures
    let apiData: any
    if (rawAnalytics.success && rawAnalytics.data) {
      apiData = rawAnalytics.data
    } else if (rawAnalytics.data) {
      apiData = rawAnalytics.data  
    } else {
      apiData = rawAnalytics
    }
    
    if (!apiData) return null
    console.log('Raw API Data:', apiData)
    
    // Transform API response to match expected interface structure
    const transformedData: EnhancedAnalyticsData = {
      overview: {
        totalTasks: apiData.tasks?.totalTasks || apiData.overview?.totalTasks || 0,
        completedTasks: apiData.tasks?.completedTasks || apiData.overview?.completedTasks || 0,
        overdueTasks: apiData.tasks?.overdueTasks || apiData.overview?.overdueTasks || 0,
        totalTeamMembers: apiData.team?.summary?.totalTeamMembers || apiData.overview?.totalTeamMembers || 0,
        totalProjects: apiData.overview?.totalProjects || 1,
        activeProjects: apiData.overview?.activeProjects || 0,
        completedProjects: apiData.overview?.completedProjects || 0,
        onHoldProjects: apiData.overview?.onHoldProjects || 0,
        averageProgress: apiData.overview?.averageProgress || 0,
        totalBudget: apiData.overview?.totalBudget || apiData.resources?.budget?.total || 0,
        totalSpent: apiData.overview?.totalSpent || apiData.resources?.budget?.actualCosts || 0,
        budget: {
          allocated: apiData.resources?.budget?.allocated || apiData.overview?.totalBudget || 0,
          spent: apiData.resources?.budget?.actualCosts || apiData.overview?.totalSpent || 0,
          remaining: (apiData.overview?.totalBudget || 0) - (apiData.overview?.totalSpent || 0),
        },
        timeline: {
          totalDays: 0,
          daysPassed: 0,
          daysRemaining: 0,
          isOnTrack: (apiData.kpi?.timelineHealth || 0) > 70,
        },
      },
      
      tasks: {
        _id: apiData.tasks?._id || null,
        totalTasks: apiData.tasks?.totalTasks || 0,
        completedTasks: apiData.tasks?.completedTasks || 0,
        inProgressTasks: apiData.tasks?.inProgressTasks || 0,
        pendingTasks: apiData.tasks?.pendingTasks || 0,
        overdueTasks: apiData.tasks?.overdueTasks || 0,
      },
      
      kpi: {
        taskCompletion: apiData.kpi?.taskCompletion || 0,
        budgetUtilization: apiData.kpi?.budgetUtilization || 0,
        teamProductivity: apiData.kpi?.teamProductivity || 0,
        timelineHealth: apiData.kpi?.timelineHealth || 0,
        overallHealth: apiData.kpi?.overallHealth || 0,
      },
      
      team: {
        departments: apiData.team?.departments || [],
        individuals: apiData.team?.individuals || [],
        summary: apiData.team?.summary || {
          totalDepartments: 0,
          totalTeamMembers: 0,
          avgDepartmentProductivity: 0,
          avgIndividualProductivity: 0,
        },
      },
      
      
      resources: {
        budget: {
          total: apiData.resources?.budget?.total || 0,
          allocated: apiData.resources?.budget?.allocated || 0,
          actualCosts: apiData.resources?.budget?.actualCosts || 0,
          utilization: apiData.resources?.budget?.utilization || 0,
          variance: apiData.resources?.budget?.variance || 0,
          breakdown: apiData.resources?.budget?.breakdown || {},
        },
        hours: {
          totalEstimated: apiData.resources?.hours?.totalEstimated || 0,
          totalActual: apiData.resources?.hours?.totalActual || 0,
          completedEstimated: apiData.resources?.hours?.completedEstimated || 0,
          completedActual: apiData.resources?.hours?.completedActual || 0,
          efficiency: apiData.resources?.hours?.efficiency || 100,
          variance: apiData.resources?.hours?.variance || 0,
        },
        utilization: apiData.resources?.utilization || {
          assignedTasks: 0,
          unassignedTasks: 0,
          utilizationRate: 100,
          totalTasks: 0,
        },
        summary: apiData.resources?.summary || {
          overallEfficiency: 100,
          budgetHealth: 'good',
          resourceHealth: 'good',
        },
      },
      
      collaboration: {
        departmentCollaboration: apiData.collaboration?.departmentCollaboration || 0,
        crossDepartmentTasks: apiData.collaboration?.crossDepartmentTasks || 0,
        communicationScore: apiData.collaboration?.communicationScore || 85,
      },
      
      performance: {
        completionRate: apiData.kpi?.taskCompletion || 0,
        averageTaskDuration: 0,
        productivityScore: apiData.kpi?.teamProductivity || 0,
        qualityScore: 0,
      },
      
      trends: {
        tasksCompleted: [],
        teamEfficiency: [],
      },
      
      risks: apiData.risks || [],
      insights: apiData.insights || [],
      meta: apiData.meta,
    }
    
    console.log('Transformed Analytics Data:', transformedData)
    return transformedData
  }, [rawAnalytics])

  // Extract insights from the analytics data
  const insights: AnalyticsInsight[] = useMemo(() => {
    return analytics?.insights || []
  }, [analytics])

  return {
    analytics,
    insights,
    loading: isLoading,
    error: error?.message || null,
    refetch,
  }
}

// Dashboard analytics hook (all projects)
export function useDashboardAnalytics(dateRange: '7d' | '30d' | '90d' | '1y' = '30d') {
  const { 
    analytics,
    setFilters,
    setDateRange,
    refreshAnalytics,
    ...rest 
  } = useAnalytics()

  // Set date range filter automatically and clear project filter
  useMemo(() => {
    if (dateRange !== rest.filters.dateRange || rest.filters.projectId) {
      setFilters({ projectId: undefined, includeCompleted: true })
      setDateRange(dateRange)
    }
  }, [dateRange, rest.filters.dateRange, rest.filters.projectId, setFilters, setDateRange])

  return {
    analytics,
    ...rest,
    refreshAnalytics: () => refreshAnalytics(),
  }
}

// Specific metric hooks for easier access
export function useTaskMetrics(projectId?: string) {
  const { analytics, loading, error } = projectId 
    ? useProjectAnalytics(projectId)
    : useDashboardAnalytics()
  
  return {
    metrics: (analytics && !Array.isArray(analytics)) ? {
      totalTasks: (analytics as any).overview?.totalTasks || 0,
      completedTasks: (analytics as any).overview?.completedTasks || 0,
      overdueTasks: (analytics as any).overview?.overdueTasks || 0,
      completionRate: (analytics as any).performance?.completionRate || 0
    } : null,
    loading,
    error,
  }
}

export function usePerformanceMetrics(projectId?: string) {
  const { analytics, loading, error } = projectId 
    ? useProjectAnalytics(projectId)
    : useDashboardAnalytics()
  
  return {
    metrics: (analytics && !Array.isArray(analytics)) ? analytics.performance : null,
    loading,
    error,
  }
}

export function useRiskAssessment(projectId?: string) {
  const { analytics, loading, error } = projectId 
    ? useProjectAnalytics(projectId)
    : useDashboardAnalytics()
  
  return {
    risks: (analytics && !Array.isArray(analytics)) ? analytics.risks || [] : [],
    loading,
    error,
  }
}

// Helper hooks for computed values - now using Redux insights
export function useAnalyticsInsights(projectId?: string) {
  const { insights, loading, error } = projectId 
    ? useProjectAnalytics(projectId)
    : useDashboardAnalytics()

  return {
    insights: insights || [],
    loading,
    error,
  }
}

// Analytics auto-refresh utility hook - exposes refetch globally
export function useAnalyticsAutoRefresh(projectId: string, refetch: () => Promise<any>) {
  const queryClient = useQueryClient()
  
  useEffect(() => {
    if (!projectId || !refetch) {
      return
    }
    
    console.log('🔵 [ANALYTICS] Registering for project:', projectId);
    
    // Store refetch function globally so CRUD hooks can call it
    (window as any).__analyticsRefetch = {
      projectId,
      refetch: async () => {
        console.log('🔄 [ANALYTICS] Refresh triggered for project:', projectId)
        // Remove ALL analytics cache completely
        queryClient.removeQueries({ queryKey: ['project-analytics'] })
        queryClient.removeQueries({ queryKey: ['analytics'] })
        await new Promise(resolve => setTimeout(resolve, 100))
        const result = await refetch()
        console.log('✅ [ANALYTICS] Refresh complete')
        return result
      },
      invalidate: async () => {
        await queryClient.invalidateQueries({ 
          queryKey: ['project-analytics', projectId],
          refetchType: 'active'
        })
      }
    }
    
    console.log('✅ [ANALYTICS] Registered successfully for project:', projectId)
    
    return () => {
      if ((window as any).__analyticsRefetch?.projectId === projectId) {
        console.log('🔴 [ANALYTICS] Unregistering for project:', projectId)
        delete (window as any).__analyticsRefetch
      }
    }
  }, [projectId, refetch, queryClient])
}