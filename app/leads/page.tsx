"use client";

import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAppSelector } from "@/hooks/redux";
import { useLeads } from "@/hooks/use-leads";
import { useDebounceSearch } from "@/hooks/use-debounced-search";
import PageHeader from "@/components/shared/page-header";
import DataTable, { ColumnDef, ActionMenuItem } from "@/components/shared/data-table";
import GenericFilter, { FilterConfig } from "@/components/shared/generic-filter";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import CustomModal from "@/components/shared/custom-modal";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Lead, LeadFilters, LeadSort } from "@/types";
import {
  User,
  Calendar,
  AlertTriangle,
  Briefcase,
  DollarSign,
  UserPlus,
  Mail,
  Phone,
  MapPin,
  Target,
  Clock
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { usePermissions } from "@/hooks/use-permissions";
import { formatCurrency } from "@/lib/utils";
import { handleAPIError } from "@/lib/utils/api-client";
import Swal from 'sweetalert2';
import { useNavigation } from "@/components/providers/navigation-provider";
import GenericReportExporter from "@/components/shared/GenericReportExporter";
import { PRIORITY_COLORS, STATUS_COLORS } from '@/lib/colorConstants';

export default function LeadsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { canCreate } = usePermissions();
  const { navigateTo, isNavigating } = useNavigation()
  const {
    leads: hookLeads,
    loading: hookLoading,
    actionLoading: hookActionLoading,
    error: hookError,
    fetchLeads,
    deleteLead,
    restoreLead,
    createClientFromLead,
    setFilters,
    setSort,
    setPagination,
    clearError,
    setSelectedLead
  } = useLeads();

  // Redux state for filters, sort, pagination (these are managed by Redux for persistence)
  const {
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.leads);

  // Use hook data and loading states
  const leads = hookLeads;
  const loading = hookLoading;
  const error = hookError;

  // Local state
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [isQuickViewOpen, setIsQuickViewOpen] = useState(false);
  const [selectedLeadForView, setSelectedLeadForView] = useState<Lead | null>(null);
  const [activeTab, setActiveTab] = useState('overview');


  // Filter configuration
  const filterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: 'search',
        label: 'Search',
        type: 'text',
        placeholder: 'Search leads...',
        cols: 12,
        mdCols: 3,
      },
      {
        key: 'status',
        label: 'Status',
        type: 'select',
        searchable: true,
        placeholder: 'All Statuses',
        cols: 12,
        mdCols: 3,
        options: [
          { value: 'all', label: 'All Statuses' },
          { value: 'active', label: 'Active' },
          { value: 'inactive', label: 'Inactive' },
          { value: 'qualified', label: 'Qualified' },
          { value: 'unqualified', label: 'Unqualified' },
        ],
      },
      {
        key: 'source',
        label: 'Source',
        type: 'select',
        searchable: true,
        placeholder: 'All Sources',
        cols: 12,
        mdCols: 3,
        options: [
          { value: 'all', label: 'All Sources' },
          { value: 'website', label: 'Website' },
          { value: 'referral', label: 'Referral' },
          { value: 'cold_call', label: 'Cold Call' },
          { value: 'email', label: 'Email Marketing' },
          { value: 'social_media', label: 'Social Media' },
          { value: 'event', label: 'Event/Conference' },
          { value: 'other', label: 'Other' },
        ],
      },
      {
        key: 'priority',
        label: 'Priority',
        type: 'select',
        searchable: true,
        placeholder: 'All Priorities',
        cols: 12,
        mdCols: 3,
        options: [
          { value: 'all', label: 'All Priorities' },
          { value: 'low', label: 'Low' },
          { value: 'medium', label: 'Medium' },
          { value: 'high', label: 'High' },
          { value: 'urgent', label: 'Urgent' },
        ],
      },
    ],
    defaultValues: {
      search: '',
      status: 'all',
      source: 'all',
      priority: 'all',
    },
  }), []);

  // Map Redux filters to UI filters (convert empty strings to 'all' for selects)
  const uiFilters = useMemo(() => ({
    search: filters.search || '',
    status: filters.status || 'all',
    source: filters.source || 'all',
    priority: filters.priority || 'all',
  }), [filters.search, filters.status, filters.source, filters.priority]);

  // Filter handlers - Updated to match clients page pattern
  const handleFilterChange = useCallback((newFilters: Record<string, any>) => {
    // Convert 'all' values back to empty strings for the API
    const leadFilters: LeadFilters = {
      search: newFilters.search || '',
      status: newFilters.status === 'all' ? '' : (newFilters.status || ''),
      source: newFilters.source === 'all' ? '' : (newFilters.source || ''),
      priority: newFilters.priority === 'all' ? '' : (newFilters.priority || ''),
    };
    setFilters(leadFilters);
  }, [setFilters]);

  const handleFilterReset = useCallback(() => {
    const defaultFilters: LeadFilters = {
      search: '',
      status: '',
      source: '',
      priority: '',
    };
    setFilters(defaultFilters);
  }, [setFilters]);

  // Table columns configuration
  const columns: ColumnDef<Lead>[] = [
    {
      key: 'name',
      label: 'Lead Info',
      sortable: true,
      render: (value, row) => (
        <div className="flex items-center space-x-3">
          <div className="flex-shrink-0">
            <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center">
              <User className="h-5 w-5 text-primary" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="font-medium text-foreground">{value}</span>
            <span className="text-sm text-muted-foreground">{row.email}</span>
            {row.company && (
              <span className="text-xs text-muted-foreground">{row.company}</span>
            )}
          </div>
        </div>
      ),
    },
    {
      key: 'projectName',
      label: 'Project',
      sortable: true,
      render: (value, row) => (
        <div className="flex flex-col">
          <span className="font-medium">{value}</span>
          {/* {row.projectBudget && (
            <span className="text-sm text-green-600">
              <DollarSign className="h-3 w-3 inline mr-1" />
              {formatCurrency(row.projectBudget)}
            </span>
          )} */}
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (value) => {
        return (
          <Badge className={`${STATUS_COLORS[value as keyof typeof STATUS_COLORS] || STATUS_COLORS.inactive} border`}>
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </Badge>
        );
      },
    },
    {
      key: 'source',
      label: 'Source',
      sortable: true,
      render: (value) => value ? value.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()) : 'Unknown',
    },
    {
      key: 'priority',
      label: 'Priority',
      sortable: true,
      render: (value) => {
        return (
          <Badge className={`${PRIORITY_COLORS[value as keyof typeof PRIORITY_COLORS] || PRIORITY_COLORS.low} border`}>
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </Badge>
        );
      },
    },
    {
      key: 'nextFollowUpDate',
      label: 'Follow Up',
      sortable: true,
      render: (value) => value ? (
        <div className="flex items-center text-sm">
          <Calendar className="h-3 w-3 mr-1 text-muted-foreground" />
          {new Date(value).toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
          })}
        </div>
      ) : (
        <span className="text-sm text-muted-foreground italic">Not scheduled</span>
      ),
    },
    {
      key: 'createdAt',
      label: 'Created',
      sortable: true,
      render: (value) => new Date(value).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      }),
    },
  ];



  // Handle creating client from lead
  const handleCreateClientFromLead = useCallback(async (lead: Lead) => {
    try {
      // Show confirmation dialog
      const result = await Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Create Client from Lead',
        text: `Are you sure you want to create a client account for ${lead.name}? This will qualify the lead and create a new client profile.`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Yes, Create Client',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3B82F6',
        cancelButtonColor: '#6B7280',
      });

      if (!result.isConfirmed) return;

      // Call API to create client from lead
      const leadId = (lead._id || (lead as any).id)?.toString()
      if (!leadId) {
        throw new Error('Invalid lead id')
      }

      const responseData = await createClientFromLead(leadId);

      toast({
        title: "Success",
        description: `Client created successfully for ${lead.name}`,
      });

      // Navigate to client edit page
      navigateTo(`/clients/edit/${responseData.client._id}`);

    } catch (error: any) {
      console.error('Error creating client from lead:', error);
      toast({
        variant: "destructive",
        title: "Error",
        description: error.message || "Failed to create client from lead",
      });
    }
  }, [createClientFromLead, toast, navigateTo]);


  // Custom actions for DataTable
  const customActions: ActionMenuItem<Lead>[] = [
    {
      label: "Create Client",
      icon: <UserPlus className="h-4 w-4" />,
      onClick: handleCreateClientFromLead,
      disabled: (lead: Lead) => {
        // Disable if lead is not active or already has a client
        return lead.status !== 'active' || !!lead.clientId;
      },
      hasPermission: () => canCreate('clients'),
      hideIfNoPermission: true,
    },
  ];


  // Event handlers
  const handleSort = useCallback((field: keyof Lead, direction: "asc" | "desc") => {
    setSort({ field: field as any, direction });
  }, [setSort]);

  const handlePageChange = useCallback((page: number) => {
    setPagination({ page });
  }, [setPagination]);

  const handlePageSizeChange = useCallback((limit: number) => {
    setPagination({ limit, page: 1 });
  }, [setPagination]);

  const handleEditLead = useCallback((lead: Lead) => {
    navigateTo(`/leads/edit/${lead._id}`);
  }, [router]);

  // Refs to track previous values and prevent unnecessary calls
  const prevParamsRef = useRef<string>('')

  // Memoize filters and sort to prevent unnecessary re-renders
  const memoizedFilters = useMemo(() => ({
    search: filters.search,
    status: filters.status,
    source: filters.source,
    priority: filters.priority
  }), [filters.search, filters.status, filters.source, filters.priority])

  const memoizedSort = useMemo(() => ({
    field: sort.field,
    direction: sort.direction
  }), [sort.field, sort.direction])

  const memoizedPagination = useMemo(() => ({
    page: pagination.page,
    limit: pagination.limit
  }), [pagination.page, pagination.limit])

  const handleViewLead = useCallback((lead: Lead) => {
    setSelectedLeadForView(lead);
    setIsQuickViewOpen(true);
    setActiveTab('overview');
  }, []);

  const handleDeleteLead = useCallback(async (lead: Lead) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Delete ${lead.name}?`,
      text: "Are you sure you want to delete this lead?",
      icon: "error",
      showCancelButton: true,
      showConfirmButton: true,
      confirmButtonText: "Yes, Delete",
      cancelButtonText: "No",
      confirmButtonColor: "#dc2626",
    });

    if (result.isConfirmed) {
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Deleting...',
        text: 'Please wait while we delete the lead.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await deleteLead(lead._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Deleted!",
          text: "Lead has been deleted successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Lead deleted successfully.",
          variant: "default",
        });

        fetchLeads();
      } catch (err: any) {
        // Show error message
        console.log('Delete Lead Error:', err);
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: err.error,
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(err, "Failed to delete lead. Please try again.");
      }
    }
  }, [deleteLead, toast, fetchLeads]);

  const handleRestoreLead = useCallback(async (lead: Lead) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Restore ${lead.name}?`,
      text: "Are you sure you want to restore this lead?",
      icon: "question",
      showCancelButton: true,
      showConfirmButton: true,
      confirmButtonText: "Yes, Restore",
      cancelButtonText: "No",
      confirmButtonColor: "#10b981",
    });

    if (result.isConfirmed) {
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Restoring...',
        text: 'Please wait while we restore the lead.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await restoreLead(lead._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Restored!",
          text: "Lead has been restored successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Lead restored successfully.",
          variant: "default",
        });

        fetchLeads();
      } catch (error: any) {
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: error.error,
          icon: "error",
          confirmButtonText: "OK"
        });
        handleAPIError(error, "Failed to restore lead. Please try again.");
      }
    }
  }, [restoreLead, toast, fetchLeads]);

  // Fetch leads effect - only when parameters actually change
  useEffect(() => {
    // Create a key from current parameters
    const currentParamsKey = JSON.stringify({
      page: memoizedPagination.page,
      limit: memoizedPagination.limit,
      search: memoizedFilters.search,
      status: memoizedFilters.status,
      source: memoizedFilters.source,
      priority: memoizedFilters.priority,
      sortField: memoizedSort.field,
      sortDirection: memoizedSort.direction
    })

    // Only fetch if parameters have changed
    if (currentParamsKey !== prevParamsRef.current) {
      prevParamsRef.current = currentParamsKey

      fetchLeads({
        page: memoizedPagination.page,
        limit: memoizedPagination.limit,
        filters: memoizedFilters,
        sort: memoizedSort,
      })
    }
  }, [memoizedPagination.page, memoizedPagination.limit, memoizedFilters.search, memoizedFilters.status, memoizedFilters.source, memoizedFilters.priority, memoizedSort.field, memoizedSort.direction, fetchLeads])

  // Error handling effect
  useEffect(() => {
    if (error) {
      toast({
        title: "Error",
        description: error,
        variant: "destructive",
      });
      clearError?.();
    }
  }, [error, toast, clearError])

  // Clear error when component unmounts
  useEffect(() => {
    return () => {
      clearError?.();
    };
  }, [clearError]);

  // Stats display
  const statsCards = useMemo(() => {
    // Use Redux stats if available, otherwise calculate from current data
    const displayStats = stats ? {
      totalLeads: stats.totalLeads,
      activeLeads: stats.activeLeads,
      qualifiedLeads: stats.qualifiedLeads,
      unqualifiedLeads: stats.unqualifiedLeads,
      inactiveLeads: stats.inactiveLeads,
    } : {
      totalLeads: leads.length,
      activeLeads: leads.filter(l => l.status === 'active').length,
      qualifiedLeads: leads.filter(l => l.status === 'qualified').length,
      unqualifiedLeads: leads.filter(l => l.status === 'unqualified').length,
      inactiveLeads: leads.filter(l => l.status === 'inactive').length,
    };

    // Calculate conversion rate
    const conversionRate = displayStats.totalLeads > 0 ?
      (displayStats.qualifiedLeads / displayStats.totalLeads) * 100 : 0;

    return [
      {
        title: "Total Leads",
        value: displayStats.totalLeads,
        icon: <Briefcase className="h-8 w-8 text-muted-foreground" />,
        color: "text-muted-foreground"
      },
      {
        title: "Active",
        value: displayStats.activeLeads,
        icon: (
          <div className="h-8 w-8 bg-blue-100 rounded-full flex items-center justify-center">
            <div className="h-3 w-3 bg-blue-600 rounded-full" />
          </div>
        ),
        color: "text-blue-600"
      },
      {
        title: "Qualified",
        value: displayStats.qualifiedLeads,
        icon: (
          <div className="h-8 w-8 bg-green-100 rounded-full flex items-center justify-center">
            <div className="h-3 w-3 bg-green-600 rounded-full" />
          </div>
        ),
        color: "text-green-600"
      },
      {
        title: "Unqualified",
        value: displayStats.unqualifiedLeads,
        icon: (
          <div className="h-8 w-8 bg-red-100 rounded-full flex items-center justify-center">
            <div className="h-3 w-3 bg-red-600 rounded-full" />
          </div>
        ),
        color: "text-red-600"
      },
      {
        title: "Conversion",
        value: `${conversionRate.toFixed(1)}%`,
        icon: (
          <div className="h-8 w-8 bg-orange-100 rounded-full flex items-center justify-center">
            <div className="h-3 w-3 bg-orange-600 rounded-full" />
          </div>
        ),
        color: "text-orange-600"
      },
    ];
  }, [leads, stats]);


  return (
    <div className="space-y-6">
      <PageHeader
        title="Leads"
        subtitle="Manage and track your sales leads"
        onAddClick={() => navigateTo("/leads/add")}
        addButtonText="Add Lead"

        // Filter functionality - Updated to match clients page
        showFilterButton={true}
        hasActiveFilters={Object.values(uiFilters).some(v => v && v !== 'all' && v !== '')}
        isFilterExpanded={isFilterExpanded}
        onFilterToggle={() => {
          setIsFilterExpanded(!isFilterExpanded);
        }}
        activeFiltersCount={Object.values(uiFilters).filter(v => v && v !== 'all' && v !== '').length}
        filterText="Filter Leads"

        // Refresh functionality
        showRefreshButton={true}
        onRefresh={handleFilterReset}
        isRefreshing={loading}
        actions={
          <GenericReportExporter
            moduleName="leads"
            data={leads}
            onExportComplete={(result) => {
              if (result.success) {
                toast({
                  title: "Success",
                  description: result.message,
                  variant: "default",
                });
              } else {
                toast({
                  title: "Error",
                  description: result.message,
                  variant: "destructive",
                });
              }
            }}
          />
        }
      >
        {/* Generic Filter - Updated to match clients page */}
        {isFilterExpanded && (
          <GenericFilter
            config={filterConfig}
            values={uiFilters}
            onFilterChange={handleFilterChange}
            onReset={handleFilterReset}
            loading={loading}
          />
        )}
      </PageHeader>

      {/* Error Display */}
      {error && (
        <Alert variant="destructive" className="border-destructive bg-destructive/10">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error.error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-4">
        <DataTable
          data={leads}
          columns={columns}
          loading={loading}
          NoOfCards={5}
          totalCount={pagination.total}
          pageSize={pagination.limit}
          currentPage={pagination.page}
          onPageChange={handlePageChange}
          onPageSizeChange={handlePageSizeChange}
          onSort={handleSort}
          statsCards={statsCards}
          sortColumn={sort.field}
          sortDirection={sort.direction}
          emptyMessage="No leads found"
          resourceName="leads"
          customActions={customActions}
          onView={handleViewLead}
          onDelete={handleDeleteLead}
          onRestore={handleRestoreLead}
          enablePermissionChecking={true}
        />
      </div>

      {/* Quick View Modal */}
      <CustomModal
        isOpen={isQuickViewOpen}
        onClose={() => setIsQuickViewOpen(false)}
        title="Lead Details"
        modalSize="lg"
      >
        {selectedLeadForView && (
          <div className="space-y-4">
            {/* Tab Navigation */}
            <div className="border-b border-border">
              <nav className="flex" aria-label="Tabs">
                {[{
                  id: 'overview', name: 'Overview'
                },
                { id: 'project', name: 'Project Details' },
                { id: 'followup', name: 'Follow-up' }
                ].map((tab) => (
                  <div className="flex-1" key={tab.id}>
                    <button
                      onClick={() => setActiveTab(tab.id)}
                      className={cn(
                        "w-full text-center whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm transition-colors",
                        activeTab === tab.id
                          ? "border-primary text-primary"
                          : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
                      )}
                    >
                      {tab.name}
                    </button>
                  </div>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="mt-4">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  {/* Lead Header */}
                  <div className="flex items-center space-x-4">
                    <div className="w-16 h-16 bg-primary/10 rounded-lg flex items-center justify-center">
                      <User className="h-8 w-8 text-primary" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedLeadForView.name}</h3>
                      <p className="text-muted-foreground">{selectedLeadForView.email}</p>
                    </div>
                  </div>

                  {/* Lead Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Company</label>
                      <p className="mt-1">{selectedLeadForView.company || 'Not specified'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Status</label>
                      <div className="mt-1">
                        <Badge className={cn(
                          "border",
                          selectedLeadForView.status === 'active'
                            ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300 border-blue-200 dark:border-blue-800'
                            : selectedLeadForView.status === 'qualified'
                              ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border-green-200 dark:border-green-800'
                              : selectedLeadForView.status === 'unqualified'
                                ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300 border-red-200 dark:border-red-800'
                                : 'bg-muted text-muted-foreground border-border'
                        )}>
                          {selectedLeadForView.status?.charAt(0).toUpperCase() + selectedLeadForView.status?.slice(1)}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Source</label>
                      <p className="mt-1">{selectedLeadForView.source ? selectedLeadForView.source.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()) : 'Unknown'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Priority</label>
                      <div className="mt-1">
                        <Badge className={cn(
                          "border",
                          selectedLeadForView.priority === 'urgent'
                            ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300 border-red-200 dark:border-red-800'
                            : selectedLeadForView.priority === 'high'
                              ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-300 border-orange-200 dark:border-orange-800'
                              : selectedLeadForView.priority === 'medium'
                                ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800'
                                : 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-300 border-gray-200 dark:border-gray-800'
                        )}>
                          {selectedLeadForView.priority?.charAt(0).toUpperCase() + selectedLeadForView.priority?.slice(1)}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Phone</label>
                      <p className="mt-1 flex items-center">
                        <Phone className="h-4 w-4 mr-2 text-muted-foreground" />
                        {selectedLeadForView.phone || 'Not provided'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Location</label>
                      <p className="mt-1 flex items-center">
                        <MapPin className="h-4 w-4 mr-2 text-muted-foreground" />
                        {/* {selectedLeadForView.address || 'Not specified'} */}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Created</label>
                      <p className="mt-1">
                        {new Date(selectedLeadForView.createdAt as any).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Last Updated</label>
                      <p className="mt-1">
                        {new Date(selectedLeadForView.updatedAt as any).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Project Details Tab */}
              {activeTab === 'project' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Project Information</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Details about the potential project
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Project Name */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                        <Briefcase className="h-4 w-4 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Project Name</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedLeadForView.projectName || 'Not specified'}
                        </p>
                      </div>
                    </div>

                    {/* Project Description */}
                    {selectedLeadForView.projectDescription && (
                      <div className="flex items-start space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center mt-0.5">
                          <Target className="h-4 w-4 text-green-600" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Project Description</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {selectedLeadForView.projectDescription}
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Budget */}
                    {selectedLeadForView.projectBudget && (
                      <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                          <DollarSign className="h-4 w-4 text-green-600" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Budget</p>
                          <p className="text-xs text-muted-foreground">
                            {typeof selectedLeadForView.projectBudget === 'number'
                              ? formatCurrency(selectedLeadForView.projectBudget)
                              : selectedLeadForView.projectBudget
                            }
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Timeline */}
                    {selectedLeadForView.projectTimeline && (
                      <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                          <Clock className="h-4 w-4 text-purple-600" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Timeline</p>
                          <p className="text-xs text-muted-foreground">
                            {selectedLeadForView.projectTimeline}

                          </p>
                        </div>
                      </div>
                    )}

                    {/* Requirements */}
                    {selectedLeadForView.projectRequirements && (
                      <div className="flex items-start space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center mt-0.5">
                          <AlertTriangle className="h-4 w-4 text-orange-600" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Requirements</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {selectedLeadForView.projectRequirements.map((item, index) => (
                              <span key={index} className="block">
                                <b>{index + 1}.</b> {item}
                              </span>
                            ))}
                          </p>
                        </div>
                      </div>
                    )}
                    {/* Requirements */}
                    {selectedLeadForView.customerServices && (
                      <div className="flex items-start space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center mt-0.5">
                          <AlertTriangle className="h-4 w-4 text-orange-600" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Customer Services</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {selectedLeadForView.customerServices.map((item, index) => (
                              <span key={index} className="block">
                                <b>{index + 1}.</b> {item}
                              </span>
                            ))}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Follow-up Tab */}
              {activeTab === 'followup' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Follow-up Information</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Communication and follow-up details
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Next Follow-up Date */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedLeadForView.nextFollowUpDate
                          ? "bg-blue-100 dark:bg-blue-900/20"
                          : "bg-gray-100 dark:bg-gray-900/20"
                      )}>
                        <Calendar className={cn(
                          "h-4 w-4",
                          selectedLeadForView.nextFollowUpDate ? "text-blue-600" : "text-gray-600"
                        )} />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Next Follow-up</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedLeadForView.nextFollowUpDate
                            ? new Date(selectedLeadForView.nextFollowUpDate).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'long',
                              day: 'numeric'
                            })
                            : 'Not scheduled'
                          }
                        </p>
                      </div>
                    </div>

                    {/* Last Contact Date */}
                    {selectedLeadForView.lastContactDate && (
                      <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                          <Mail className="h-4 w-4 text-green-600" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Last Contact</p>
                          <p className="text-xs text-muted-foreground">
                            {new Date(selectedLeadForView.lastContactDate).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'long',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit'
                            })}
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Contact Method */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                        <Phone className="h-4 w-4 text-purple-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Preferred Contact</p>
                        <p className="text-xs text-muted-foreground">
                          Email: {selectedLeadForView.email}
                          {selectedLeadForView.phone && ` • Phone: ${selectedLeadForView.phone}`}
                        </p>
                      </div>
                    </div>

                    {/* Notes */}
                    {selectedLeadForView.notes && (
                      <div className="flex items-start space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-yellow-100 dark:bg-yellow-900/20 flex items-center justify-center mt-0.5">
                          <span className="text-yellow-600 text-sm">📝</span>
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Notes</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {selectedLeadForView.notes}
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Lead Priority for Follow-up */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedLeadForView.priority === 'urgent'
                          ? "bg-red-100 dark:bg-red-900/20"
                          : selectedLeadForView.priority === 'high'
                            ? "bg-orange-100 dark:bg-orange-900/20"
                            : selectedLeadForView.priority === 'medium'
                              ? "bg-yellow-100 dark:bg-yellow-900/20"
                              : "bg-gray-100 dark:bg-gray-900/20"
                      )}>
                        <span className={cn(
                          "text-sm font-bold",
                          selectedLeadForView.priority === 'urgent'
                            ? "text-red-600"
                            : selectedLeadForView.priority === 'high'
                              ? "text-orange-600"
                              : selectedLeadForView.priority === 'medium'
                                ? "text-yellow-600"
                                : "text-gray-600"
                        )}>
                          {selectedLeadForView.priority === 'urgent' ? '🔥' : selectedLeadForView.priority === 'high' ? '⚡' : selectedLeadForView.priority === 'medium' ? '⭐' : '📌'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Follow-up Priority</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedLeadForView.priority?.charAt(0).toUpperCase() + selectedLeadForView.priority?.slice(1)} priority lead
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Actions Footer */}
            <div className="flex justify-end space-x-3 pt-4 border-t border-border">
              <Button
                variant="outline"
                onClick={() => setIsQuickViewOpen(false)}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </CustomModal>
    </div>
  );
}