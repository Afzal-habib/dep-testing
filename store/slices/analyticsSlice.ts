import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import type {
  EnhancedAnalyticsData,
  AnalyticsFilters,
  AnalyticsSort,
  AnalyticsPagination,
  AnalyticsInsight,
  AnalyticsOverview,
  AnalyticsTasks,
  AnalyticsPerformance,
  AnalyticsRisk,
  AnalyticsTrends
} from '@/hooks/use-analytics'

// Analytics slice state interface
export interface AnalyticsState {
  data: EnhancedAnalyticsData | null
  insights: AnalyticsInsight[]
  loading: boolean
  actionLoading: boolean
  error: string | null
  filters: AnalyticsFilters
  sort: AnalyticsSort
  pagination: AnalyticsPagination
  lastUpdated: Date | null
  refreshInterval: number // in milliseconds
}

// Initial state following Department pattern
const initialState: AnalyticsState = {
  data: null,
  insights: [],
  loading: false,
  actionLoading: false,
  error: null,
  filters: {
    projectId: undefined,
    dateRange: '30d',
    startDate: undefined,
    endDate: undefined,
    includeCompleted: true,
    departmentId: undefined,
    userId: undefined,
    taskStatus: [],
  },
  sort: {
    field: 'level',
    direction: 'desc',
  },
  pagination: {
    page: 1,
    limit: 10,
    total: 0,
    totalPages: 0,
  },
  lastUpdated: null,
  refreshInterval: 5 * 60 * 1000, // 5 minutes default
}

// Analytics slice with reducers following Department pattern
const analyticsSlice = createSlice({
  name: 'analytics',
  initialState,
  reducers: {
    // Data management
    setAnalyticsData: (state, action: PayloadAction<EnhancedAnalyticsData>) => {
      state.data = action.payload
      state.loading = false
      state.error = null
      state.lastUpdated = new Date()
    },

    setAnalyticsInsights: (state, action: PayloadAction<AnalyticsInsight[]>) => {
      state.insights = action.payload
    },

    // Loading states
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
      if (action.payload) {
        state.error = null
      }
    },

    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },

    // Error handling
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload
      state.loading = false
      state.actionLoading = false
    },

    clearError: (state) => {
      state.error = null
    },

    // Filters and sorting
    setFilters: (state, action: PayloadAction<Partial<AnalyticsFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
      // Clear data when filters change to trigger refresh
      if (Object.keys(action.payload).length > 0) {
        state.data = null
        state.lastUpdated = null
      }
    },

    clearFilters: (state) => {
      state.filters = initialState.filters
      state.data = null
      state.lastUpdated = null
    },

    setSort: (state, action: PayloadAction<AnalyticsSort>) => {
      state.sort = action.payload
    },

    // Pagination (mainly for risks)
    setPagination: (state, action: PayloadAction<Partial<AnalyticsPagination>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },

    // Refresh management
    setRefreshInterval: (state, action: PayloadAction<number>) => {
      state.refreshInterval = action.payload
    },

    setLastUpdated: (state, action: PayloadAction<Date | null>) => {
      state.lastUpdated = action.payload
    },

    // Quick metric updates (for real-time updates)
    updateOverviewMetrics: (state, action: PayloadAction<Partial<AnalyticsOverview>>) => {
      if (state.data) {
        state.data.overview = { ...state.data.overview, ...action.payload }
      }
    },

    updateTaskMetrics: (state, action: PayloadAction<Partial<AnalyticsTasks>>) => {
      if (state.data) {
        state.data.tasks = { ...state.data.tasks, ...action.payload }
      }
    },


    updatePerformanceMetrics: (state, action: PayloadAction<Partial<AnalyticsPerformance>>) => {
      if (state.data) {
        state.data.performance = { ...state.data.performance, ...action.payload }
      }
    },

    // Risk management
    addRisk: (state, action: PayloadAction<AnalyticsRisk>) => {
      if (state.data) {
        state.data.risks.push(action.payload)
      }
    },

    updateRisk: (state, action: PayloadAction<{ index: number; updates: Partial<AnalyticsRisk> }>) => {
      if (state.data && state.data.risks[action.payload.index]) {
        state.data.risks[action.payload.index] = {
          ...state.data.risks[action.payload.index],
          ...action.payload.updates
        }
      }
    },

    removeRisk: (state, action: PayloadAction<number>) => {
      if (state.data) {
        state.data.risks.splice(action.payload, 1)
      }
    },

    setRisks: (state, action: PayloadAction<AnalyticsRisk[]>) => {
      if (state.data) {
        state.data.risks = action.payload
      }
    },

    // Trend data updates
    updateTrendData: (state, action: PayloadAction<Partial<AnalyticsTrends>>) => {
      if (state.data) {
        state.data.trends = { ...state.data.trends, ...action.payload }
      }
    },

    // Reset state
    resetState: (state) => {
      return initialState
    },

    // Cache management
    invalidateCache: (state) => {
      state.data = null
      state.insights = []
      state.lastUpdated = null
    },

    // Date range presets
    setDateRangePreset: (state, action: PayloadAction<'7d' | '30d' | '90d' | '1y'>) => {
      const now = new Date()
      const dateRange = action.payload
      
      state.filters.dateRange = dateRange
      state.filters.endDate = now

      switch (dateRange) {
        case '7d':
          state.filters.startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
          break
        case '30d':
          state.filters.startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
          break
        case '90d':
          state.filters.startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000)
          break
        case '1y':
          state.filters.startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000)
          break
      }

      state.data = null
      state.lastUpdated = null
    },

    setCustomDateRange: (state, action: PayloadAction<{ startDate: Date; endDate: Date }>) => {
      state.filters.dateRange = 'custom'
      state.filters.startDate = action.payload.startDate
      state.filters.endDate = action.payload.endDate
      state.data = null
      state.lastUpdated = null
    },
  },
})

// Export actions
export const {
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
  updateOverviewMetrics,
  updateTaskMetrics,
  updatePerformanceMetrics,
  addRisk,
  updateRisk,
  removeRisk,
  setRisks,
  updateTrendData,
  resetState,
  invalidateCache,
  setDateRangePreset,
  setCustomDateRange,
} = analyticsSlice.actions

// Export reducer
export default analyticsSlice.reducer

// Selector helpers for derived state
export const selectAnalyticsOverview = (analytics: EnhancedAnalyticsData | null) =>
  analytics?.overview || null

export const selectAnalyticsTaskMetrics = (analytics: EnhancedAnalyticsData | null) =>
  analytics?.tasks || null


export const selectAnalyticsPerformanceMetrics = (analytics: EnhancedAnalyticsData | null) =>
  analytics?.performance || null

export const selectAnalyticsRisks = (analytics: EnhancedAnalyticsData | null) =>
  analytics?.risks || []

export const selectHighPriorityRisks = (analytics: EnhancedAnalyticsData | null) =>
  analytics?.risks?.filter(risk => risk.level === 'high' || risk.level === 'critical') || []

export const selectAnalyticsTrends = (analytics: EnhancedAnalyticsData | null) =>
  analytics?.trends || null

export const selectIsDataStale = (lastUpdated: Date | null, refreshInterval: number) => {
  if (!lastUpdated) return true
  return Date.now() - lastUpdated.getTime() > refreshInterval
}