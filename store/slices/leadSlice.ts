import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { Lead, LeadFilters, LeadSort } from '@/types'

interface LeadState {
  leads: Lead[]
  selectedLead: Lead | null
  loading: boolean
  actionLoading: boolean
  error: any
  filters: LeadFilters
  sort: LeadSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: {
    totalLeads: number
    activeLeads: number
    inactiveLeads: number
    qualifiedLeads: number
    unqualifiedLeads: number
  } | null
}

const initialState: LeadState = {
  leads: [],
  selectedLead: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {},
  sort: { field: 'createdAt', direction: 'desc' },
  pagination: { page: 1, limit: 10, total: 0, pages: 0 },
  stats: null,
}

const leadSlice = createSlice({
  name: "leads",
  initialState,
  reducers: {
    setLeads: (state, action: PayloadAction<Lead[]>) => {
      state.leads = action.payload
    },
    setSelectedLead: (state, action: PayloadAction<Lead | null>) => {
      state.selectedLead = action.payload
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
    },
    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },
    setError: (state, action: PayloadAction<any>) => {
      state.error = action.payload
    },
    clearError: (state) => {
      state.error = null
    },
    setFilters: (state, action: PayloadAction<LeadFilters>) => {
      state.filters = action.payload
      state.pagination.page = 1
    },
    setSort: (state, action: PayloadAction<LeadSort>) => {
      state.sort = action.payload
    },
    setPagination: (state, action: PayloadAction<Partial<LeadState["pagination"]>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    setStats: (state, action: PayloadAction<LeadState["stats"]>) => {
      state.stats = action.payload
    },
    resetState: (state) => {
      return initialState
    },
  },
})

export const {
  setLeads,
  setSelectedLead,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState
} = leadSlice.actions

export default leadSlice.reducer
