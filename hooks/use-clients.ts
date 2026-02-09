import { useCallback, useMemo, useState } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
} from './use-generic-query'
import {
  setFilters,
  setSort,
  setPagination,
  setSelectedClient,
  clearError,
  resetState,
  optimisticStatusUpdate,
} from '@/store/slices/clientSlice'
import type {
  UpdateClientData,
  ClientFilters,
  ClientSort,
  CreateClientData,
  Client,
} from '@/types'

export function useClients() {
  const dispatch = useAppDispatch()

  // Local state for fetching client by ID
  const [clientIdToFetch, setClientIdToFetch] = useState<string | undefined>(undefined)

  const {
    selectedClient,
    filters,
    sort,
    pagination,
  } = useAppSelector((state) => state.clients)

  // Generic options for clients
  const genericOptions = useMemo(() => ({
    entityName: 'clients',
    baseUrl: '/api/clients',
    reduxDispatchers: {
      setEntities: (clients: Client[]) => {
        // This will be handled by TanStack Query, but we can dispatch if needed
      },
      setEntity: (client: Client | null) => dispatch(setSelectedClient(client)),
      setPagination: (pagination: any) => dispatch(setPagination(pagination)),
      setStats: (stats: any) => {
        // Stats will be handled by TanStack Query
      },
      setLoading: () => { },
      setActionLoading: () => { },
      setError: (error: any) => {
        // Error handling is done by handleAPIError
      },
      clearError: () => dispatch(clearError()),
    },
  }), [dispatch])

  // Query params from Redux state
  const queryParams = useMemo(() => ({
    page: pagination.page,
    limit: pagination.limit,
    filters,
    sort,
  }), [pagination.page, pagination.limit, filters, sort])

  // Generic queries
  const {
    data: clients = [],
    isLoading: loading,
    refetch: refetchClients,
  } = useGenericQuery<Client>(genericOptions, queryParams)

  // Fetch single client by ID
  const { data: fetchedClientById, isLoading: clientByIdLoading } = useGenericQueryById<Client>(
    {
      entityName: 'clients',
      baseUrl: '/api/clients',
      reduxDispatchers: {
        setEntity: (entity: Client | null) => dispatch(setSelectedClient(entity)),
        setLoading: (loading: boolean) => {
          // Loading handled by query
        },
        setError: (error: any) => {
          // Error handled in generic hook
        },
        clearError: () => dispatch(clearError()),
      },
    },
    clientIdToFetch,
    !!clientIdToFetch
  )

  // Mutations
  const createMutation = useGenericCreate<Client>(genericOptions)
  const updateMutation = useGenericUpdate<Client>(genericOptions)
  const deleteMutation = useGenericDelete<Client>(genericOptions)

  // Fetch operations
  const handleFetchClients = useCallback(() => {
    refetchClients()
  }, [refetchClients])

  const handleFetchClientById = useCallback(async (id: string) => {
    // Set the client ID to fetch
    setClientIdToFetch(id)
  }, [])

  // CRUD operations
  const handleCreateClient = useCallback(async (clientData: CreateClientData) => {
    return await createMutation.mutateAsync(clientData)
  }, [createMutation])

  const handleUpdateClient = useCallback(async (id: string, data: UpdateClientData) => {
    return await updateMutation.mutateAsync({ id, data })
  }, [updateMutation])

  const handleDeleteClient = useCallback(async (clientId: string) => {
    return await deleteMutation.mutateAsync(clientId)
  }, [deleteMutation])

  const handleRestoreClient = useCallback(async (clientId: string) => {
    // First get the current client to preserve clientStatus
    const currentClient = clients.find(c => c._id === clientId)
    if (!currentClient) {
      throw new Error('Client not found')
    }

    return await updateMutation.mutateAsync({
      id: clientId,
      data: {
        isDeleted: false,
        status: 'active',
        clientStatus: currentClient.clientStatus // Preserve existing clientStatus
      }
    })
  }, [updateMutation, clients])

  // Status operations with business logic
  const handleUpdateClientStatus = useCallback(async (id: string, clientStatus: string, reason?: string) => {
    // Optimistic update for better UX
    dispatch(optimisticStatusUpdate({ id, clientStatus }))

    try {
      const result = await updateMutation.mutateAsync({
        id,
        data: { clientStatus, ...(reason && { unqualifiedReason: reason }) }
      })
      return result
    } catch (error) {
      // The slice will handle reverting the optimistic update on failure
      throw error
    }
  }, [dispatch, updateMutation])

  const handleQualifyClient = useCallback((id: string) => {
    return handleUpdateClientStatus(id, 'qualified')
  }, [handleUpdateClientStatus])

  const handleUnqualifyClient = useCallback((id: string, reason: string) => {
    return handleUpdateClientStatus(id, 'unqualified', reason)
  }, [handleUpdateClientStatus])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<ClientFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: ClientSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: { page?: number; limit?: number }) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  const handleSetSelectedClient = useCallback((client: any) => {
    dispatch(setSelectedClient(client))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetState = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshClients = useCallback(() => {
    return handleFetchClients()
  }, [handleFetchClients])

  // Computed values
  const hasClients = clients.length > 0
  const isFirstPage = pagination.page === 1
  const isLastPage = pagination.page >= pagination.pages
  const totalPages = pagination.pages
  const totalItems = pagination.total

  // Business logic helpers
  const canUnqualifyClient = useCallback((client: any) => {
    return client.clientStatus === 'qualified'
  }, [])

  const canEditClient = useCallback((client: any) => {
    // Clients can always be edited (unlike leads which have status restrictions)
    return true
  }, [])

  const canDeleteClient = useCallback((client: any) => {
    // Only support department can delete clients (will be enforced on API level)
    return client.clientStatus !== 'qualified' || client.status === 'inactive'
  }, [])

  const getClientStatusBadgeColor = useCallback((status: string) => {
    switch (status) {
      case 'qualified': return 'success'
      case 'unqualified': return 'destructive'
      default: return 'secondary'
    }
  }, [])

  const getStatusBadgeColor = useCallback((status: string) => {
    switch (status) {
      case 'active': return 'success'
      case 'inactive': return 'secondary'
      case 'suspended': return 'warning'
      default: return 'secondary'
    }
  }, [])

  const getClientsByStatus = useCallback((clientStatus: string) => {
    return clients.filter(client => client.clientStatus === clientStatus)
  }, [clients])

  const getClientsWithLeads = useCallback(() => {
    return clients.filter(client => client.leadId)
  }, [clients])

  const getClientsWithoutLeads = useCallback(() => {
    return clients.filter(client => !client.leadId)
  }, [clients])

  const getClientsByCompany = useCallback((company: string) => {
    return clients.filter(client =>
      client.company?.toLowerCase().includes(company.toLowerCase())
    )
  }, [clients])

  // Lead-related helpers
  const navigateToLead = useCallback((client: any) => {
    if (client.leadId) {
      return `/leads/edit/${client.leadId}`
    }
    return null
  }, [])

  const hasLinkedLead = useCallback((client: any) => {
    return Boolean(client.leadId)
  }, [])

  // Computed stats
  const stats = useMemo(() => ({
    totalClients: clients.length,
    qualifiedClients: clients.filter(c => c.clientStatus === 'qualified').length,
    unqualifiedClients: clients.filter(c => c.clientStatus === 'unqualified').length,
    activeClients: clients.filter(c => c.status === 'active').length,
  }), [clients])

  return {
    // State - combine Redux state with TanStack Query data
    clients: clients,
    selectedClient: fetchedClientById || selectedClient,
    loading: loading || createMutation.isPending || updateMutation.isPending || deleteMutation.isPending,
    actionLoading: createMutation.isPending || updateMutation.isPending || deleteMutation.isPending,
    statusLoading: updateMutation.isPending, // For status updates
    error: null, // TanStack Query handles errors
    filters,
    sort,
    pagination,
    stats,

    // Individual loading states
    queryLoading: loading,
    clientByIdLoading,

    // CRUD operations
    fetchClients: handleFetchClients,
    fetchClientById: handleFetchClientById,
    createClient: handleCreateClient,
    updateClient: handleUpdateClient,
    deleteClient: handleDeleteClient,
    restoreClient: handleRestoreClient,

    // Status operations
    updateClientStatus: handleUpdateClientStatus,
    qualifyClient: handleQualifyClient,
    unqualifyClient: handleUnqualifyClient,

    // Filter and sort operations
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,
    setSelectedClient: handleSetSelectedClient,

    // Utility operations
    clearError: () => { }, // Not needed with TanStack Query
    resetState: handleResetState,
    refreshClients,

    // Computed values
    hasClients,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Business logic helpers
    canUnqualifyClient,
    canEditClient,
    canDeleteClient,
    getClientStatusBadgeColor,
    getStatusBadgeColor,
    getClientsByStatus,
    getClientsWithLeads,
    getClientsWithoutLeads,
    getClientsByCompany,

    // Lead-related helpers
    navigateToLead,
    hasLinkedLead,
  }
}


