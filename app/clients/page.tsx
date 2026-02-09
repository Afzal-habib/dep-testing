"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useClients } from "@/hooks/use-clients";
import PageHeader from "@/components/shared/page-header";
import DataTable, { ColumnDef, ActionMenuItem } from "@/components/shared/data-table";
import GenericFilter, { FilterConfig } from "@/components/shared/generic-filter";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import CustomModal from "@/components/shared/custom-modal";
import { Client, ClientFilters, ClientSort, Project } from "@/types";
import { Building2, Users, User, Mail, Phone, FolderPlus, MapPin, Calendar } from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { usePermissions } from "@/hooks/use-permissions";
import Swal from 'sweetalert2';
import { handleAPIError } from "@/lib/utils/api-client";
import { useNavigation } from "@/components/providers/navigation-provider";
import GenericReportExporter from "@/components/shared/GenericReportExporter";
import { STATUS_COLORS } from '@/lib/colorConstants';

export default function ClientsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { canCreate } = usePermissions();
  const { navigateTo, isNavigating } = useNavigation()

  // Hooks
  const {
    clients,
    loading,
    error,
    pagination,
    filters,
    sort,
    stats,
    setFilters,
    setSort,
    setPagination,
    fetchClients,
    deleteClient,
    restoreClient,
    clearError,
  } = useClients();

  // Local state
  const [selectedClient, setSelectedClient] = useState<Client | null>(null);
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [isQuickViewOpen, setIsQuickViewOpen] = useState(false);
  const [selectedClientForView, setSelectedClientForView] = useState<Client | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  // Filter configuration
  const filterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: 'search',
        label: 'Search',
        type: 'text',
        placeholder: 'Search clients...',
        cols: 12,
        mdCols: 6,
        lgCols: 6,
      },
      {
        key: 'status',
        label: 'Status',
        type: 'select',
        searchable: true,
        placeholder: 'All Statuses',
        cols: 12,
        mdCols: 6,
        lgCols: 6,
        options: [
          { value: 'all', label: 'All Statuses' },
          { value: 'qualified', label: 'Qualified' },
          { value: 'unqualified', label: 'Unqualified' },
        ],
      },
    ],
    defaultValues: {
      search: '',
      status: 'all',
    },
  }), []);

  // Map Redux filters to UI filters (convert empty strings to 'all' for selects)
  const uiFilters = useMemo(() => ({
    search: filters.search || '',
    status: filters.status || 'all',
  }), [filters.search, filters.status]);
  const navigateToProject = useCallback((projectId: string) => {
    // Navigate to edit tab of project detail page
    if (typeof window !== 'undefined') {
      localStorage.setItem('project-details-active-tab', 'overview');
    }
    navigateTo(`/projects/${projectId}`);
  }, [navigateTo]);

  // Filter handlers
  const handleFilterChange = useCallback((newFilters: Record<string, any>) => {
    // Convert 'all' values back to empty strings for the API
    const clientFilters: ClientFilters = {
      search: newFilters.search || '',
      status: newFilters.status === 'all' ? '' : (newFilters.status || ''),
    };
    setFilters(clientFilters);
  }, [setFilters]);

  const handleFilterReset = useCallback(() => {
    const defaultFilters: ClientFilters = {
      search: '',
      status: '',
    };
    setFilters(defaultFilters);
  }, [setFilters]);

  // Table columns configuration
  const columns: ColumnDef<Client>[] = [
    {
      key: 'name',
      label: 'Client Info',
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
            <div className="flex items-center text-sm text-muted-foreground">
              <Mail className="h-3 w-3 mr-1" />
              {row.email}
            </div>
            {row.phone && (
              <div className="flex items-center text-xs text-muted-foreground">
                <Phone className="h-3 w-3 mr-1" />
                {row.phone}
              </div>
            )}
          </div>
        </div>
      ),
    },
    {
      key: 'company',
      label: 'Company',
      sortable: true,
      render: (value) => (
        <div className="flex items-center">
          <Building2 className="h-4 w-4 mr-2 text-muted-foreground" />
          <span className="font-medium">{value}</span>
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
      key: "projects" as any,
      label: "Projects",
      render: (value: any, row: Client) => {
        return (
          <div className="flex flex-wrap gap-1">
            {row.projects?.length == 0 && (<span className="text-muted-foreground">No projects yet</span>
            )}
            {row.projects?.slice(0, 2).map((project) => (
              <Badge onClick={() => navigateToProject(project._id)} key={project._id} variant="outline" className="text-xs cursor-pointer hover:bg-accent hover:text-accent-foreground">
                {project.name}
              </Badge>
            ))}
            {(row.projects?.length || 0) > 2 && (
              <Badge variant="outline" className="text-xs">
                +{(row.projects?.length || 0) - 2} more
              </Badge>
            )}
          </div>
        );
      },
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
    {
      key: 'updatedAt',
      label: 'Last Updated',
      sortable: true,
      render: (value) => new Date(value).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      }),
    },
  ];


  // Handle creating project from client
  const handleCreateProjectFromClient = useCallback(async (client: Client) => {
    try {
      if (!client._id) {
        throw new Error('Client ID is required');
      }

      const params = new URLSearchParams();
      params.set('clientId', client._id);
      params.set('prefill', 'true');
      
      navigateTo(`/projects/add?${params.toString()}`);

    } catch (error: any) {
      console.log('Error navigating to create project:', error);
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to navigate to project creation",
      });
    }
  }, [router, toast]);

  // Custom actions for DataTable
  const customActions: ActionMenuItem<Client>[] = [
    {
      label: "Create Project",
      icon: <FolderPlus className="h-4 w-4" />,
      onClick: handleCreateProjectFromClient,
      disabled: (client: Client) => client?.leadId?._id == '' || (client as any).projects.length !=0,
      hasPermission: () => canCreate('projects'),
      hideIfNoPermission: true,
    },
  ];

  // Event handlers
  const handleSort = useCallback((field: string, direction: "asc" | "desc") => {
    const validSortFields: (keyof Client)[] = ['name', 'email', 'company', 'clientStatus', 'status', 'createdAt', 'updatedAt'];
    if (validSortFields.includes(field as keyof Client)) {
      setSort({ field: field as ClientSort['field'], direction });
    }
  }, [setSort]);

  const handlePageChange = useCallback((page: number) => {
    setPagination({ page });
  }, [setPagination]);

  const handlePageSizeChange = useCallback((limit: number) => {
    setPagination({ limit, page: 1 });
  }, [setPagination]);

  const handleViewClient = useCallback((client: Client) => {
    setSelectedClientForView(client);
    setIsQuickViewOpen(true);
    setActiveTab('overview');
  }, []);

  const handleDeleteClient = useCallback(async (client: Client) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Delete ${client.name}?`,
      text: "Are you sure you want to delete this client?",
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
        text: 'Please wait while we delete the client.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await deleteClient(client._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Deleted!",
          text: "Client has been deleted successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Client deleted successfully.",
          variant: "default",
        });

        fetchClients();
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
        handleAPIError(error, "Failed to delete user. Please try again.");
      }
    }
  }, [deleteClient, toast, fetchClients]);

  const handleRestoreClient = useCallback(async (client: Client) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Restore ${client.name}?`,
      text: "Are you sure you want to restore this client?",
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
        text: 'Please wait while we restore the client.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await restoreClient(client._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Restored!",
          text: "Client has been restored successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Client restored successfully.",
          variant: "default",
        });

        fetchClients();
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
        handleAPIError(error, "Failed to restore client. Please try again.");
      }
    }
  }, [restoreClient, toast, fetchClients]);

  // Error handling effect
  useEffect(() => {
    if (error) {
      toast({
        title: "Error",
        description: error,
        variant: "destructive",
      });
      clearError();
    }
  }, [error, toast, clearError]);

  // Clear error when component unmounts
  useEffect(() => {
    return () => {
      clearError();
    };
  }, [clearError]);

  // Stats display
  const statsCards = useMemo(() => {
    if (!stats) return [];
    return [
      {
        title: "Total",
        value: stats.totalClients,
        icon: <Users className="h-4 w-4" />,
        color: "text-muted-foreground"
      },
      {
        title: "Qualified",
        value: stats.qualifiedClients,
        icon: (
          <div className="h-8 w-8 bg-green-100 rounded-full flex items-center justify-center">
            <div className="h-3 w-3 bg-green-600 rounded-full" />
          </div>
        ),
        color: "text-green-600"
      },
      {
        title: "Unqualified",
        value: stats.unqualifiedClients,
        icon: (
          <div className="h-8 w-8 bg-red-100 rounded-full flex items-center justify-center">
            <div className="h-3 w-3 bg-red-600 rounded-full" />
          </div>
        ),
        color: "text-red-600"
      },
      {
        title: "Active",
        value: stats.activeClients || 0,
        icon: <Building2 className="h-4 w-4" />,
        color: "text-blue-600"
      }
    ];
  }, [stats]);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Clients"
        subtitle="Manage your qualified clients and their information"
        onAddClick={() => navigateTo("/clients/add")}
        addButtonText="Add Client"
        showAddButton={canCreate("clients")}

        // Filter functionality
        showFilterButton={true}
        hasActiveFilters={Object.values(uiFilters).some(v => v && v !== 'all' && v !== '')}
        isFilterExpanded={isFilterExpanded}
        onFilterToggle={() => {
          setIsFilterExpanded(!isFilterExpanded);
        }}
        activeFiltersCount={Object.values(uiFilters).filter(v => v && v !== 'all' && v !== '').length}
        filterText="Filter Clients"
        // Refresh functionality
        showRefreshButton={true}
        onRefresh={handleFilterReset}
        isRefreshing={loading}
        actions={
          <GenericReportExporter
            moduleName="clients"
            data={clients}
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
        {/* Generic Filter */}
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

      <div className="space-y-4">
        {/* Data Table */}
        <DataTable
          data={clients}
          columns={columns}
          loading={loading}
          totalCount={pagination.total}
          pageSize={pagination.limit}
          currentPage={pagination.page}
          onPageChange={handlePageChange}
          onPageSizeChange={handlePageSizeChange}
          onSort={handleSort}
          sortColumn={sort.field}
          sortDirection={sort.direction}
          emptyMessage="No clients found"
          resourceName="clients"
          customActions={customActions}
          onView={handleViewClient}
          onDelete={handleDeleteClient}
          onRestore={handleRestoreClient}
          enablePermissionChecking={true}
          statsCards={statsCards}
        />
      </div>

      {/* Quick View Modal */}
      <CustomModal
        isOpen={isQuickViewOpen}
        onClose={() => setIsQuickViewOpen(false)}
        title="Client Details"
        modalSize="lg"
      >
        {selectedClientForView && (
          <div className="space-y-4">
            {/* Tab Navigation */}
            <div className="border-b border-border">
              <nav className="flex" aria-label="Tabs">
                {[{
                  id: 'overview', name: 'Overview'
                },
                { id: 'projects', name: 'Projects' },
                { id: 'activity', name: 'Activity' }
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
                  {/* Client Header */}
                  <div className="flex items-center space-x-4">
                    <div className="w-16 h-16 bg-primary/10 rounded-lg flex items-center justify-center">
                      <User className="h-8 w-8 text-primary" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedClientForView.name}</h3>
                      <p className="text-muted-foreground">{selectedClientForView.email}</p>
                    </div>
                  </div>

                  {/* Client Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Company</label>
                      <p className="mt-1 flex items-center">
                        <Building2 className="h-4 w-4 mr-2 text-muted-foreground" />
                        {selectedClientForView.company || 'Not specified'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Status</label>
                      <div className="mt-1">
                        <Badge className={cn(
                          "border",
                          selectedClientForView.status === 'qualified'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border-green-200 dark:border-green-800'
                            : 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300 border-red-200 dark:border-red-800'
                        )}>
                          {selectedClientForView.status?.charAt(0).toUpperCase() + selectedClientForView.status?.slice(1)}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Phone</label>
                      <p className="mt-1 flex items-center">
                        <Phone className="h-4 w-4 mr-2 text-muted-foreground" />
                        {selectedClientForView.phone || 'Not provided'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Location</label>
                      <p className="mt-1 flex items-center">
                        <MapPin className="h-4 w-4 mr-2 text-muted-foreground" />
                        {/* {selectedClientForView?.address || 'Not specified'} */}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Created</label>
                      <p className="mt-1">
                        {new Date(selectedClientForView.createdAt as any).toLocaleDateString('en-US', {
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
                        {new Date(selectedClientForView.updatedAt as any).toLocaleDateString('en-US', {
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

              {/* Projects Tab */}
              {activeTab === 'projects' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Client Projects</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Projects associated with this client
                    </p>
                  </div>

                  <div className="space-y-3">

                    {/* Client Status for Projects */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedClientForView.status === 'qualified'
                          ? "bg-green-100 dark:bg-green-900/20"
                          : "bg-red-100 dark:bg-red-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedClientForView.status === 'qualified' ? "text-green-600" : "text-red-600"
                        )}>
                          {selectedClientForView.status === 'qualified' ? '✓' : '✗'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Project Eligibility</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedClientForView.status === 'qualified'
                            ? 'Qualified for new projects'
                            : 'Not qualified for new projects'
                          }
                        </p>
                      </div>
                    </div>

                    {/* Budget Information */}
                    {/* {selectedClientForView?.budget && (
                      <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                          <span className="text-green-600 text-sm">$</span>
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Budget Range</p>
                          <p className="text-xs text-muted-foreground">
                            {selectedClientForView.budget}
                          </p>
                        </div>
                      </div>
                    )} */}
                  </div>
                </div>
              )}

              {/* Activity Tab */}
              {activeTab === 'activity' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Client Activity</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Recent activity and important events
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Client Registration */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                        <User className="h-4 w-4 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Client Registration</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(selectedClientForView.createdAt as any).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                      </div>
                    </div>

                    {/* Status Update */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedClientForView.status === 'qualified'
                          ? "bg-green-100 dark:bg-green-900/20"
                          : "bg-red-100 dark:bg-red-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedClientForView.status === 'qualified' ? "text-green-600" : "text-red-600"
                        )}>
                          {selectedClientForView.status === 'qualified' ? '✓' : '⚠'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">
                          Status: {selectedClientForView.status?.charAt(0).toUpperCase() + selectedClientForView.status?.slice(1)}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Current client qualification status
                        </p>
                      </div>
                    </div>

                    {/* Last Update */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                        <Calendar className="h-4 w-4 text-purple-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Last Updated</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(selectedClientForView.updatedAt as any).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                      </div>
                    </div>

                    {/* Contact Information */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center">
                        <Mail className="h-4 w-4 text-orange-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Contact Methods</p>
                        <p className="text-xs text-muted-foreground">
                          Email: {selectedClientForView.email}
                          {selectedClientForView.phone && ` • Phone: ${selectedClientForView.phone}`}
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