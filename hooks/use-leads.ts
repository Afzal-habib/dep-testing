import { useCallback, useMemo } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import {
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
  resetState,
} from '@/store/slices/leadSlice'
import type {
  FetchLeadsParams,
  LeadFilters,
  LeadSort,
  Lead
} from '@/types'
import type { CreateLeadData, UpdateLeadData } from '@/lib/validations/lead'

export function useLeads() {
  const dispatch = useAppDispatch()

  const {
    leads,
    selectedLead,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.leads)

  // Define options for generic hooks
  const leadOptions: UseGenericQueryOptions<any> = {
    entityName: 'leads',
    baseUrl: '/api/leads',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setLeads(entities)),
      setEntity: (entity) => dispatch(setSelectedLead(entity)),
      setPagination: (pagination) => dispatch(setPagination(pagination)),
      setStats: (stats) => dispatch(setStats(stats)),
      setLoading: (loading) => dispatch(setLoading(loading)),
      setActionLoading: (loading) => dispatch(setActionLoading(loading)),
      setError: (error) => dispatch(setError(error)),
      clearError: () => dispatch(clearError()),
    },
  }

  // Memoize query params to prevent unnecessary re-renders
  const queryParams = useMemo(() => ({
    page: pagination.page,
    limit: pagination.limit,
    filters,
    sort: {
      field: sort.field,
      direction: sort.direction as 'asc' | 'desc',
    },
  }), [pagination.page, pagination.limit, filters, sort.field, sort.direction])

  const allLeadsParams = useMemo(() => ({
    page: 1,
    limit: 100,
    filters: {},
    sort: {
      field: 'createdAt' as const,
      direction: 'desc' as const,
    },
  }), [])

  // Use generic hooks
  const { data: fetchedLeads, isLoading: queryLoading, refetch: refetchLeads } = useGenericQuery(
    leadOptions,
    queryParams,
    true
  )

  // Separate query for fetching all leads (for filters/dropdowns)
  const { data: allLeads } = useGenericQuery(
    leadOptions,
    allLeadsParams,
    true
  )

  const createMutation = useGenericCreate(leadOptions)
  const updateMutation = useGenericUpdate(leadOptions)
  const deleteMutation = useGenericDelete(leadOptions)

  // Fetch operations - Stable function that doesn't change on re-renders
  const handleFetchLeads = useCallback((params?: FetchLeadsParams) => {
    refetchLeads()
  }, [refetchLeads])

  // CRUD operations
  const handleCreateLead = useCallback((leadData: CreateLeadData) => {
    return createMutation.mutateAsync(leadData)
  }, [createMutation])

  const handleUpdateLead = useCallback((id: string, data: UpdateLeadData) => {
    return updateMutation.mutateAsync({ id, data })
  }, [updateMutation])

  const handleDeleteLead = useCallback((leadId: string) => {
    return deleteMutation.mutateAsync(leadId)
  }, [deleteMutation])

  const handleRestoreLead = useCallback(async (leadId: string) => {
    return await updateMutation.mutateAsync({
      id: leadId,
      data: {
        isDeleted: false,
        status: 'active'
      }
    })
  }, [updateMutation])

  // Status operations with business logic
  const handleUpdateLeadStatus = useCallback(async (id: string, status: string, reason?: string) => {
    const result = await updateMutation.mutateAsync({
      id,
      data: { status, ...(reason && { unqualifiedReason: reason }) }
    })
    return result
  }, [updateMutation])

  const handleQualifyLead = useCallback((id: string) => {
    return handleUpdateLeadStatus(id, 'qualified')
  }, [handleUpdateLeadStatus])

  const handleUnqualifyLead = useCallback((id: string, reason: string) => {
    return handleUpdateLeadStatus(id, 'unqualified', reason)
  }, [handleUpdateLeadStatus])

  const handleActivateLead = useCallback((id: string) => {
    return handleUpdateLeadStatus(id, 'active')
  }, [handleUpdateLeadStatus])

  const handleDeactivateLead = useCallback((id: string) => {
    return handleUpdateLeadStatus(id, 'inactive')
  }, [handleUpdateLeadStatus])

  // Create client from lead operation
  const handleCreateClientFromLead = useCallback(async (leadId: string) => {
    const response = await fetch(`/api/leads/${leadId}/create-client`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const responseData = await response.json();

    if (!responseData.success) {
      const details = responseData.details && Array.isArray(responseData.details) ? responseData.details.map((d: any) => d.message || d).join(', ') : ''
      throw new Error((responseData.error || 'Failed to create client') + (details ? `: ${details}` : ''));
    }

    return responseData;
  }, [])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<LeadFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: LeadSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: { page?: number; limit?: number }) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  const handleSetSelectedLead = useCallback((lead: any) => {
    dispatch(setSelectedLead(lead))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetLeads = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshLeads = useCallback(() => {
    return handleFetchLeads()
  }, [handleFetchLeads])

  // Computed values
  const hasLeads = (fetchedLeads || leads).length > 0
  const isFirstPage = pagination.page === 1
  const isLastPage = pagination.page >= pagination.pages
  const totalPages = pagination.pages
  const totalItems = pagination.total

  // Lead utilities
  const getLeadById = useCallback((leadId: string) => {
    return (fetchedLeads || leads).find(lead => lead._id === leadId)
  }, [fetchedLeads, leads])

  const getActiveLeads = useCallback(() => {
    return (fetchedLeads || leads).filter(lead => lead.status === 'active')
  }, [fetchedLeads, leads])

  // Business logic helpers
  const canQualifyLead = useCallback((lead: any) => {
    return lead.status === 'active' || lead.status === 'inactive'
  }, [])

  const canUnqualifyLead = useCallback((lead: any) => {
    return lead.status === 'qualified'
  }, [])

  const canEditLead = useCallback((lead: any) => {
    return lead.status !== 'qualified' && lead.status !== 'unqualified'
  }, [])

  const canDeleteLead = useCallback((lead: any) => {
    return lead.status !== 'qualified'
  }, [])

  const getStatusBadgeColor = useCallback((status: string) => {
    switch (status) {
      case 'active': return 'success'
      case 'inactive': return 'secondary'
      case 'qualified': return 'primary'
      case 'unqualified': return 'destructive'
      default: return 'secondary'
    }
  }, [])

  const getLeadsByStatus = useCallback((status: string) => {
    return leads.filter(lead => lead.status === status)
  }, [leads])

  return {
    // State
    leads: fetchedLeads || leads,
    allLeads: allLeads || [],
    selectedLead,
    loading: queryLoading || loading,
    actionLoading,
    statusLoading: updateMutation.isPending, // For status updates
    error,
    filters,
    sort,
    pagination,
    stats,

    // Actions
    fetchLeads: handleFetchLeads,
    createLead: handleCreateLead,
    updateLead: handleUpdateLead,
    deleteLead: handleDeleteLead,
    restoreLead: handleRestoreLead,
    createClientFromLead: handleCreateClientFromLead,

    // Status operations
    updateLeadStatus: handleUpdateLeadStatus,
    qualifyLead: handleQualifyLead,
    unqualifyLead: handleUnqualifyLead,
    activateLead: handleActivateLead,
    deactivateLead: handleDeactivateLead,

    // Filters and pagination
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,
    setSelectedLead: handleSetSelectedLead,

    // Utilities
    clearError: handleClearError,
    resetLeads: handleResetLeads,
    refreshLeads,

    // Computed values
    hasLeads,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Lead utilities
    getLeadById,
    getActiveLeads,

    // Business logic helpers
    canQualifyLead,
    canUnqualifyLead,
    canEditLead,
    canDeleteLead,
    getStatusBadgeColor,
    getLeadsByStatus,
  }
}