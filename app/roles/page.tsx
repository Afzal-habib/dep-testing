"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useAppSelector } from "@/hooks/redux";
import { Role, RoleFilters, FilterConfig } from "@/types";
import PageHeader from "@/components/shared/page-header";
import DataTable, { ActionMenuItem, ColumnDef } from "@/components/shared/data-table";
import GenericFilter from "@/components/shared/generic-filter";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import CustomModal from "@/components/shared/custom-modal";
import { Shield, AlertTriangle, Users, Settings } from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { usePermissions } from "@/hooks/use-permissions";
import { useRoles } from "@/hooks/use-roles";
import { handleAPIError } from "@/lib/utils/api-client";
import Swal from 'sweetalert2';
import { useNavigation } from "@/components/providers/navigation-provider";
import GenericReportExporter from "@/components/shared/GenericReportExporter";

export default function RolesPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { canCreate, canUpdate } = usePermissions();
  const { navigateTo, isNavigating } = useNavigation()
  // Local state
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [isQuickViewOpen, setIsQuickViewOpen] = useState(false);
  const [selectedRoleForView, setSelectedRoleForView] = useState<Role | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  const {
    roles: hookRoles,
    loading: hookLoading,
    actionLoading: hookActionLoading,
    error: hookError,
    fetchRoles,
    deleteRole,
    restoreRole,
    setFilters,
    setSort,
    setPagination,
    clearError,
    setSelectedRole
  } = useRoles();


  // Redux state for filters, sort, pagination (these are managed by Redux for persistence)
  const {
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.roles);

  // Use hook data and loading states
  const roles = hookRoles;
  const loading = hookLoading;
  const error = hookError;

  console.log('roles are', roles)
  // Filter configuration
  const filterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: 'search',
        label: 'Search',
        type: 'text',
        placeholder: 'Search roles...',
        cols: 12, // Full width on mobile
        mdCols: 6, // Larger width on medium screens
        lgCols: 6, // Larger width on large screens
      },
      {
        key: 'status',
        label: 'Status',
        type: 'select',
        searchable: true,
        placeholder: 'All Statuses',
        cols: 12, // Full width on mobile
        mdCols: 6, // Smaller width on medium screens
        lgCols: 6, // Smaller width on large screens
        options: [
          { value: 'all', label: 'All Statuses' },
          { value: 'active', label: 'Active' },
          { value: 'inactive', label: 'Inactive' },
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

  // Filter handlers - Updated to match clients/leads/departments page pattern
  const handleFilterChange = useCallback((newFilters: Record<string, any>) => {
    // Convert 'all' values back to empty strings for the API
    const roleFilters: RoleFilters = {
      search: newFilters.search || '',
      status: newFilters.status === 'all' ? '' : (newFilters.status || ''),
    };
    setFilters(roleFilters);
  }, [setFilters]);

  const handleFilterReset = useCallback(() => {
    const defaultFilters: RoleFilters = {
      search: '',
      status: '',
    };
    setFilters(defaultFilters);
  }, [setFilters]);

  // Table columns configuration
  const columns: ColumnDef<Role>[] = [
    {
      key: 'displayName',
      label: 'Role Name',
      sortable: true,
      render: (value, row) => (
        <div className="flex items-center space-x-3">
          <div className="flex-shrink-0">
            <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center">
              <Shield className="h-5 w-5 text-primary" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="font-medium text-foreground">{value || row.name}{`(${row?.departmentDetails?.name})`}</span>
            <span className="text-sm text-muted-foreground">
              Internal: {row.name}
            </span>
          </div>
        </div>
      ),
    },
    {
      key: 'description',
      label: 'Description',
      sortable: false,
      render: (value) => (
        <div className="max-w-xs">
          {value ? (
            <span className="text-sm text-muted-foreground line-clamp-2">
              {value}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground italic">
              No description
            </span>
          )}
        </div>
      ),
    },
    {
      key: 'hierarchyLevel',
      label: 'Hierarchy Level',
      sortable: true,
      render: (value) => (
        <div className="flex items-center">
          <Badge variant="outline" className="font-mono">
            Level {value}
          </Badge>
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (value) => {
        const statusColors = {
          active: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border-green-200 dark:border-green-800',
          inactive: 'bg-muted text-muted-foreground border-border',
          deleted: 'text-muted bg-red-600 border-white-200'
        };

        return (
          <Badge className={`${statusColors[value as keyof typeof statusColors]} border`}>
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </Badge>
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

  // Event handlers
  const handleSort = useCallback((field: keyof Role, direction: "asc" | "desc") => {
    setSort({ field, direction });
  }, [setSort]);

  const handlePageChange = useCallback((page: number) => {
    setPagination({ page });
  }, [setPagination]);

  const handlePageSizeChange = useCallback((limit: number) => {
    setPagination({ limit, page: 1 });
  }, [setPagination]);

  const handleViewRole = useCallback((role: Role) => {
    setSelectedRoleForView(role);
    setIsQuickViewOpen(true);
    setActiveTab('overview');
  }, []);

  const handleDeleteRole = useCallback(async (role: Role) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Delete ${role.displayName || role.name}?`,
      text: "Are you sure you want to delete this role?",
      icon: "error",
      showCancelButton: true,
      showConfirmButton: true,
      confirmButtonText: "Yes, Delete",
      cancelButtonText: "No",
      confirmButtonColor: "#dc2626",
    });

    if (result.isConfirmed) {
      // Show simple loading with SweetAlert's built-in loader
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Deleting...',
        text: 'Please wait while we delete the role.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await deleteRole(role._id as string);

        // Show success message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Deleted!",
          text: "Role has been deleted successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Role deleted successfully.",
          variant: "default",
        });

        fetchRoles();
      } catch (error: any) {
        // Show error message
        const errorMessage = error.error?.message || error.error || error.message || "Failed to delete role. Please try again.";
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: errorMessage,
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(error, "Failed to delete role. Please try again.");
      }
    }
  }, [deleteRole, toast, fetchRoles]);

  const handleRestoreRole = useCallback(async (role: Role) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Restore ${role.displayName || role.name}?`,
      text: "Are you sure you want to restore this role?",
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
        text: 'Please wait while we restore the role.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await restoreRole(role._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Restored!",
          text: "Role has been restored successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Role restored successfully.",
          variant: "default",
        });

        fetchRoles();
      } catch (error: any) {
        const errorMessage = error.error?.message || error.error || error.message || "Failed to restore role. Please try again.";
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: errorMessage,
          icon: "error",
          confirmButtonText: "OK"
        });
        handleAPIError(error, "Failed to restore role. Please try again.");
      }
    }
  }, [restoreRole, toast, fetchRoles]);

  // Custom actions for DataTable (Change Permissions)
  const handleChangePermissions = useCallback((role: Role) => {
    try {
      // Set selected role in redux so the permissions page can use it if needed
      setSelectedRole?.(role);
      // Navigate to the permissions editor for this role
      navigateTo?.(`/roles/permissions/${role._id}`);
    } catch (err) {
      console.error('Failed to navigate to role permissions', err);
      toast({
        title: 'Error',
        description: 'Unable to open permissions editor for this role.',
        variant: 'destructive',
      });
    }
  }, [setSelectedRole, navigateTo, toast]);

  const customActions: ActionMenuItem<Role>[] = [
    {
      label: 'Change Permissions',
      icon: <Shield className="h-4 w-4" />,
      onClick: handleChangePermissions,
      disabled: (role: Role) => role?.name === 'super_admin',
      hasPermission: () => canUpdate('roles'),
      hideIfNoPermission: true,
    },
  ];

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
  const statsCards = stats ? [
    {
      title: "Total Roles",
      value: stats.totalRoles,
      icon: <Shield className="h-8 w-8 text-muted-foreground" />,
      color: "text-muted-foreground"
    },
    {
      title: "Active",
      value: stats.activeRoles || 0,
      icon: (
        <div className="h-8 w-8 bg-green-100 rounded-full flex items-center justify-center">
          <div className="h-3 w-3 bg-green-600 rounded-full" />
        </div>
      ),
      color: "text-green-600"
    },
    {
      title: "Inactive",
      value: stats.inactiveRoles || 0,
      icon: (
        <div className="h-8 w-8 bg-gray-100 rounded-full flex items-center justify-center">
          <div className="h-3 w-3 bg-gray-600 rounded-full" />
        </div>
      ),
      color: "text-gray-600"
    },
    {
      title: "Users Assigned",
      value: stats.systemRoles || 0,
      icon: <Users className="h-8 w-8 text-blue-500" />,
      color: "text-blue-600"
    },
  ] : [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Roles"
        subtitle="Manage user roles and permissions"
        onAddClick={() => navigateTo("/roles/add")}
        addButtonText="Add Role"
        showAddButton={canCreate("roles")}

        // Filter functionality - Updated to match clients/leads/departments page
        showFilterButton={true}
        hasActiveFilters={Object.values(uiFilters).some(v => v && v !== 'all' && v !== '')}
        isFilterExpanded={isFilterExpanded}
        onFilterToggle={() => {
          setIsFilterExpanded(!isFilterExpanded);
        }}
        activeFiltersCount={Object.values(uiFilters).filter(v => v && v !== 'all' && v !== '').length}
        filterText="Filter Roles"

        // Refresh functionality
        showRefreshButton={true}
        onRefresh={handleFilterReset}
        isRefreshing={loading}

        actions={
          <GenericReportExporter
            moduleName="roles"
            data={roles}
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
        {/* Generic Filter - Updated to match clients/leads/departments page */}
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
          <AlertDescription className="text-destructive-foreground">{error.error?.message || error.error || error.message || 'An error occurred'}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-4">
        {/* Data Table */}
        <DataTable
          data={roles}
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
          emptyMessage="No roles found"
          resourceName="roles"
          onView={handleViewRole}
          onDelete={handleDeleteRole}
          onRestore={handleRestoreRole}
          customActions={customActions}
          enablePermissionChecking={true}
          statsCards={statsCards}
        />
      </div>

      {/* Quick View Modal */}
      <CustomModal
        isOpen={isQuickViewOpen}
        onClose={() => setIsQuickViewOpen(false)}
        title="Role Details"
        modalSize="lg"
      >
        {selectedRoleForView && (
          <div className="space-y-4">
            {/* Tab Navigation */}
            <div className="border-b border-border">
              <nav className="flex" aria-label="Tabs">
                {[{
                  id: 'overview', name: 'Overview'
                },
                { id: 'permissions', name: 'Permissions' },
                { id: 'usage', name: 'Usage' }
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
                  {/* Role Header */}
                  <div className="flex items-center space-x-4">
                    <div className="w-16 h-16 bg-primary/10 rounded-lg flex items-center justify-center">
                      <Shield className="h-8 w-8 text-primary" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedRoleForView.displayName || selectedRoleForView.name}</h3>
                      <p className="text-muted-foreground">Internal: {selectedRoleForView.name}</p>
                    </div>
                  </div>

                  {/* Role Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Display Name</label>
                      <p className="mt-1">{selectedRoleForView.displayName || 'Not specified'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Status</label>
                      <p className="mt-1">
                        <Badge className={cn(
                          "border",
                          selectedRoleForView.status === 'active'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border-green-200 dark:border-green-800'
                            : 'bg-muted text-muted-foreground border-border'
                        )}>
                          {selectedRoleForView.status?.charAt(0).toUpperCase() + selectedRoleForView.status?.slice(1)}
                        </Badge>
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Hierarchy Level</label>
                      <p className="mt-1">
                        <Badge variant="outline" className="font-mono">
                          Level {selectedRoleForView.hierarchyLevel}
                        </Badge>
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Permissions Count</label>
                      <p className="mt-1">{Array.isArray(selectedRoleForView.permissions) ? selectedRoleForView.permissions.length : 0}</p>
                    </div>
                    <div className="col-span-2">
                      <label className="text-sm font-medium text-muted-foreground">Description</label>
                      <p className="mt-1">{selectedRoleForView.description || 'No description provided'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Created</label>
                      <p className="mt-1">
                        {new Date(selectedRoleForView.createdAt as any).toLocaleDateString('en-US', {
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
                        {new Date(selectedRoleForView.updatedAt as any).toLocaleDateString('en-US', {
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

              {/* Permissions Tab */}
              {activeTab === 'permissions' && (
                <div className="space-y-4">
                  <div className="text-center py-2">
                    <h4 className="text-lg font-medium">{selectedRoleForView.displayName || selectedRoleForView.name} Permissions</h4>
                    <p className="text-muted-foreground text-sm mb-1">
                      Permissions granted to users with this role
                    </p>
                  </div>

                  {Array.isArray(selectedRoleForView.permissions) && selectedRoleForView.permissions.length > 0 ? (
                    <div className="space-y-3">
                      {selectedRoleForView.permissions.map((permission, index) => (
                        <div key={`${permission.resource}-${index}`} className="px-6 py-2 bg-primary/5 rounded-lg border border-primary/20">
                          <div className="flex items-center justify-between">
                            <div>
                              <span className="font-medium capitalize text-foreground block mb-2">
                                {permission.resource.replace(/_/g, ' ')}
                              </span>
                              <div className="flex gap-2 flex-wrap">
                                {Array.isArray(permission.actions) && permission.actions.map((action, actionIndex) => (
                                  <Badge key={`${action}-${actionIndex}`} variant="default" className="text-xs">
                                    {action}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <div className="w-16 h-16 mx-auto bg-muted rounded-full flex items-center justify-center mb-4">
                        <Settings className="h-8 w-8 text-muted-foreground" />
                      </div>
                      <p className="text-muted-foreground">No permissions assigned</p>
                      <p className="text-sm text-muted-foreground mt-1">
                        This role doesn't have any permissions configured
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Usage Tab */}
              {activeTab === 'usage' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Role Usage</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Information about this role's usage in the system
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Role Type */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                        <Shield className="h-4 w-4 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Role Type</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedRoleForView.hierarchyLevel <= 5 ? 'System Role' : 'Department Role'}
                        </p>
                      </div>
                    </div>

                    {/* Hierarchy Position */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                        <span className="text-purple-600 text-sm font-bold">{selectedRoleForView.hierarchyLevel}</span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Hierarchy Level</p>
                        <p className="text-xs text-muted-foreground">
                          Level {selectedRoleForView.hierarchyLevel} - {selectedRoleForView.hierarchyLevel <= 3 ? 'High Authority' : selectedRoleForView.hierarchyLevel <= 7 ? 'Mid Authority' : 'Standard Authority'}
                        </p>
                      </div>
                    </div>

                    {/* Status Information */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedRoleForView.status === 'active'
                          ? "bg-green-100 dark:bg-green-900/20"
                          : "bg-gray-100 dark:bg-gray-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedRoleForView.status === 'active' ? "text-green-600" : "text-gray-600"
                        )}>
                          {selectedRoleForView.status === 'active' ? '●' : '○'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium capitalize">
                          Role {selectedRoleForView.status}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {selectedRoleForView.status === 'active' ? 'Available for assignment' : 'Not available for new assignments'}
                        </p>
                      </div>
                    </div>

                    {/* Permission Count */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center">
                        <span className="text-orange-600 text-sm font-bold">
                          {Array.isArray(selectedRoleForView.permissions) ? selectedRoleForView.permissions.length : 0}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Permissions Assigned</p>
                        <p className="text-xs text-muted-foreground">
                          Total number of permissions this role grants
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


// stats": {
//             "totalRoles": 36,
//             "systemRoles": 3,
//             "departmentRoles": 33,