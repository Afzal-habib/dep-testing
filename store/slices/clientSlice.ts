import { createSlice, PayloadAction } from '@reduxjs/toolkit'

import { Client, ClientFilters, ClientSort } from '@/types'

interface ClientState {
  selectedClient: Client | null
  loading: boolean
  actionLoading: boolean
  statusLoading: boolean
  error: string | null
  filters: ClientFilters
  sort: ClientSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
}

const initialState: ClientState = {
  selectedClient: null,
  loading: false,
  actionLoading: false,
  statusLoading: false,
  error: null,
  filters: {},
  sort: { field: 'createdAt', direction: 'desc' },
  pagination: { page: 1, limit: 10, total: 0, pages: 0 },
}

const clientSlice = createSlice({
  name: "clients",
  initialState,
  reducers: {
    setFilters: (state, action: PayloadAction<ClientFilters>) => {
      state.filters = { ...state.filters, ...action.payload }
      // Reset pagination when filters change
      if (JSON.stringify(state.filters) !== JSON.stringify(action.payload)) {
        state.pagination.page = 1
      }
    },

    setSort: (state, action: PayloadAction<ClientSort>) => {
      state.sort = action.payload
    },

    setPagination: (state, action: PayloadAction<{ page?: number; limit?: number }>) => {
      if (action.payload.page !== undefined) {
        state.pagination.page = action.payload.page
      }
      if (action.payload.limit !== undefined) {
        state.pagination.limit = action.payload.limit
      }
    },

    setSelectedClient: (state, action: PayloadAction<Client | null>) => {
      state.selectedClient = action.payload
    },

    clearError: (state) => {
      state.error = null
    },

    resetState: (state) => {
      return initialState
    },

    // Optimistic update for status changes (if needed)
    optimisticStatusUpdate: (state, action: PayloadAction<{ id: string; clientStatus: string }>) => {
      // Since we're using TanStack Query, this might not be necessary
      // But keeping it for potential future use
    }
  }
})

export const {
  setFilters,
  setSort,
  setPagination,
  setSelectedClient,
  clearError,
  resetState,
  optimisticStatusUpdate
} = clientSlice.actions

export default clientSlice.reducer
