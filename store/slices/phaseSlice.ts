import { createSlice, PayloadAction } from '@reduxjs/toolkit'

// Interfaces for phase management
export interface Phase {
  _id: string
  title: string
  description?: string
  projectId: string
  order: number
  startDate: string
  endDate: string
  actualStartDate?: string
  actualEndDate?: string
  status: 'pending' | 'planning' | 'in-progress' | 'on-hold' | 'completed' | 'cancelled'
  progress: number
  budgetAllocation?: number
  actualCost?: number
  objectives: string[]
  deliverables: string[]
  resources: string[]
  risks: string[]
  dependencies: string[]
  approvalRequired: boolean
  approvedBy?: string
  approvedAt?: string
  isDeleted: boolean
  deletedAt?: string
  deletedBy?: string
  createdBy: string
  updatedBy?: string
  createdAt: string
  updatedAt: string
}

export interface PhaseFilters {
  search?: string
  projectId?: string
  status?: 'pending' | 'planning' | 'in-progress' | 'on-hold' | 'completed' | 'cancelled' | ''
  startDateFrom?: string
  startDateTo?: string
  endDateFrom?: string
  endDateTo?: string
}

export interface PhaseSort {
  field: 'title' | 'status' | 'order' | 'startDate' | 'endDate' | 'progress' | 'createdAt' | 'updatedAt'
  direction: 'asc' | 'desc'
}

export interface PhaseStats {
  totalPhases: number
  notStartedPhases: number
  planningPhases: number
  inProgressPhases: number
  completedPhases: number
  onHoldPhases: number
  cancelledPhases: number
  overallProgress: number
}

// State interface
interface PhaseState {
  phases: Phase[]
  selectedPhase: Phase | null
  loading: boolean
  actionLoading: boolean
  error: string | null
  filters: PhaseFilters
  sort: PhaseSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: PhaseStats | null
}

// Initial state
const initialState: PhaseState = {
  phases: [],
  selectedPhase: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {},
  sort: { field: 'order', direction: 'asc' },
  pagination: { page: 1, limit: 20, total: 0, pages: 0 },
  stats: null,
}

// Slice
const phaseSlice = createSlice({
  name: 'phases',
  initialState,
  reducers: {
    setPhases: (state, action: PayloadAction<Phase[]>) => {
      state.phases = action.payload
    },
    setSelectedPhase: (state, action: PayloadAction<Phase | null>) => {
      state.selectedPhase = action.payload
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
    },
    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload
    },
    clearError: (state) => {
      state.error = null
    },
    setFilters: (state, action: PayloadAction<Partial<PhaseFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
    },
    setSort: (state, action: PayloadAction<PhaseSort>) => {
      state.sort = action.payload
    },
    setPagination: (state, action: PayloadAction<Partial<PhaseState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    setStats: (state, action: PayloadAction<PhaseStats>) => {
      state.stats = action.payload
    },
    resetState: (state) => {
      return initialState
    },
  },
})

export const {
  setPhases,
  setSelectedPhase,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState,
} = phaseSlice.actions

export default phaseSlice.reducer