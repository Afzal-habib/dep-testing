"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { usePermissions } from "@/hooks/use-permissions";
import { Project, ProjectFilters, FilterConfig } from "@/types";
import PageHeader from "@/components/shared/page-header";
import DataTable, { ColumnDef, HtmlTextRenderer } from "@/components/shared/data-table";
import GenericFilter from "@/components/shared/generic-filter";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { Building2, AlertTriangle, Users, Calendar, DollarSign, FolderOpen, FileText, Trash2, RotateCcw } from "lucide-react";
import Swal from "sweetalert2";
import { handleAPIError } from "@/lib/utils/api-client";
import { useProjects } from "@/hooks/use-projects";
import { useDepartments } from "@/hooks/use-departments";
import { useClients } from "@/hooks/use-clients";
import { formatCurrency, cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import CustomModal from "@/components/shared/custom-modal";
import { useNavigation } from "@/components/providers/navigation-provider";
import { PRIORITY_COLORS, STATUS_COLORS } from '@/lib/colorConstants';

export default function ProjectsPage() {
  console.log('Rendering ProjectsPage component');
  const router = useRouter();
  const { toast } = useToast();
  const { canDelete } = usePermissions();
  const { navigateTo, isNavigating } = useNavigation()
  // Local state
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [isQuickViewOpen, setIsQuickViewOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [availableDepartments, setAvailableDepartments] = useState<Array<{ value: string, label: string }>>([]);
  const [availableClients, setAvailableClients] = useState<Array<{ value: string, label: string }>>([]);

  const { allDepartments } = useDepartments();
  const { clients: allClients } = useClients();
  const {
    deleteProject,
    restoreProject,
    setFilters,
    setSort,
    setPagination,
    clearError,
    setSelectedProject,
    handleApproveProject: approveProjectFn,
    fetchProjects,
    // State from hook
    projects,
    selectedProject,
    loading,
    error,
    filters,
    sort,
    pagination,
    stats
  } = useProjects();

  // Update available departments when allDepartments changes
  useEffect(() => {
    if (allDepartments && allDepartments.length > 0) {
      const departmentOptions = allDepartments
        .filter((dept) => dept._id)
        .map((dept: { _id: string; name: string }) => ({
          value: dept._id,
          label: dept.name,
        })) || [];
      setAvailableDepartments(departmentOptions);
    }
  }, [allDepartments]);

  // Update available clients when allClients changes
  useEffect(() => {
    if (allClients && allClients.length > 0) {
      const clientOptions = allClients
        .filter((client) => client._id)
        .map((client: any) => ({
          value: client._id,
          label: client.name,
        })) || [];
      setAvailableClients(clientOptions);
    }
  }, [allClients]);

  // Filter configuration
  const filterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: "search",
        label: "Search Projects",
        type: "text",
        placeholder: "Search by name, description...",
        cols: 12,
        mdCols: 4,
        lgCols: 4,
      },
      {
        key: "status",
        label: "Status",
        type: "select",
        placeholder: "All Statuses",
        cols: 12,
        mdCols: 6,
        lgCols: 2,
        options: [
          { label: "All Statuses", value: "all" },
          { label: "Pending", value: "pending" },
          { label: "Active", value: "active" },
          { label: "Approved", value: "approved" },
          { label: "Completed", value: "completed" },
          { label: "Inactive", value: "inactive" },
        ],
      },
      {
        key: "priority",
        label: "Priority",
        type: "select",
        placeholder: "All Priorities",
        cols: 12,
        mdCols: 6,
        lgCols: 2,
        options: [
          { label: "All Priorities", value: "all" },
          { label: "Low", value: "low" },
          { label: "Medium", value: "medium" },
          { label: "High", value: "high" },
          { label: "Urgent", value: "urgent" },
        ],
      },
      {
        key: 'department',
        label: 'Department',
        type: 'select',
        searchable: true,
        placeholder: 'All Departments',
        cols: 12,
        mdCols: 6,
        lgCols: 2,
        options: [
          { value: 'all', label: 'All Departments' },
          ...availableDepartments,
        ],
      },
      {
        key: 'client',
        label: 'Client',
        type: 'select',
        searchable: true,
        placeholder: 'All Clients',
        cols: 12,
        mdCols: 6,
        lgCols: 2,
        options: [
          { value: 'all', label: 'All Clients' },
          ...availableClients,
        ],
      },
    ],
    defaultValues: {
      search: '',
      status: 'all',
      priority: 'all',
      department: 'all',
      client: 'all',
    },
  }), [availableDepartments]);

  // Map Redux filters to UI filters
  const uiFilters = useMemo(() => ({
    search: filters.search || '',
    status: filters.status || 'all',
    priority: filters.priority || 'all',
    department: filters.departmentId || 'all',
    client: filters.clientId || 'all',
  }), [filters]);

  // Filter handling functions
  const handleFilterChange = useCallback((newFilters: Record<string, any>) => {
    const projectFilters: ProjectFilters = {
      search: newFilters.search || '',
      status: newFilters.status === 'all' ? '' : newFilters.status || '',
      priority: newFilters.priority === 'all' ? '' : newFilters.priority || '',
      departmentId: newFilters.department === 'all' ? '' : newFilters.department || '',
      clientId: newFilters.client === 'all' ? '' : newFilters.client || '',
    };
    setFilters(projectFilters);
  }, [setFilters]);

  const handleFilterReset = useCallback(() => {
    const defaultFilters: ProjectFilters = {
      search: '',
      status: '',
      priority: '',
      departmentId: '',
      clientId: '',
    };
    setFilters(defaultFilters);
    setIsFilterExpanded(false);
  }, [setFilters]);

  // Table columns configuration
  const columns: ColumnDef<Project>[] = [
    {
      key: "name",
      label: "Project Name",
      render: (value: any, row: Project) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.name}</span>
          {row.projectType && (
            <span className="text-sm text-muted-foreground">{row.projectType}</span>
          )}
        </div>
      ),
      sortable: true,
    },
    {
      key: "client" as any,
      label: "Client",
      render: (value: any, row: Project) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.client?.name || 'Unknown'}</span>
          <span className="text-sm text-muted-foreground">{row.client?.email}</span>
        </div>
      ),
    },
    {
      key: "status",
      label: "Status",
      render: (value: any, row: Project) => {
        const status = row.status;
        return <Badge className={STATUS_COLORS[status] || STATUS_COLORS.inactive}>{status}</Badge>;
      },
      sortable: true,
    },
    {
      key: "priority",
      label: "Priority",
      render: (value: any, row: Project) => {
        const priority = row.priority;
        return <Badge className={PRIORITY_COLORS[priority] || PRIORITY_COLORS.low}>{priority}</Badge>;
      },
      sortable: true,
    },
    {
      key: "budget",
      label: "Budget",
      render: (value: any, row: Project) => (
        row.budget ? formatCurrency(row.budget) : "Not set"
      ),
    },
    {
      key: "departments" as any,
      label: "Departments",
      render: (value: any, row: Project) => {
        return (
          <div className="flex flex-wrap gap-1">
            {row.departmentTasks?.slice(0, 2).map((dept) => (
              <Badge key={dept.departmentId} variant="outline" className="text-xs">
                {dept.departmentName}
              </Badge>
            ))}
            {(row.departmentTasks?.length || 0) > 2 && (
              <Badge variant="outline" className="text-xs">
                +{(row.departmentTasks?.length || 0) - 2} more
              </Badge>
            )}
            {
              row.departmentTasks?.length === 0 && (
                <span className="text-sm text-muted-foreground">No Departments</span>
              )
            }
          </div>
        );
      },
    },
    {
      key: "tasks" as any,
      label: "Tasks",
      render: (value: any, row: Project) => {
        let taskCount = 0;
        row.departmentTasks?.forEach(dept => {
          taskCount += dept.taskCount;
        });
        return (
          <div className="flex flex-wrap gap-1">
            {(
              <Badge variant="outline" className="text-xs">
                {taskCount}
              </Badge>
            )}
          </div>
        );
      },
    },
    {
      key: "createdAt",
      label: "Created",
      render: (value: any, row: Project) => {
        const date = new Date(row.createdAt || '').toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric'
        })
        return date;
      },
      sortable: true,
    },
  ];

  // Event handlers
  const handleSort = useCallback((field: keyof Project, direction: "asc" | "desc") => {
    setSort({ field: field as any, direction });
  }, [setSort]);

  const handlePageChange = useCallback((page: number) => {
    setPagination({ page });
  }, [setPagination]);

  const handlePageSizeChange = useCallback((limit: number) => {
    setPagination({ limit, page: 1 });
  }, [setPagination]);

  const handleViewProject = useCallback((project: Project) => {
    setSelectedProject(project);
    setIsQuickViewOpen(true);
  }, []);

  const handleDeleteProject = useCallback(async (project: Project) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: "Delete Project?",
      text: `Are you sure you want to delete "${project.name}"? This action cannot be undone.`,
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#dc2626",
      cancelButtonColor: "#6b7280",
      confirmButtonText: "Yes, delete it!",
      cancelButtonText: "Cancel",

    });

    if (result.isConfirmed) {
      // Show loading with SweetAlert's built-in loader
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Deleting...',
        text: 'Please wait while we delete the project.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await deleteProject(project._id!);

        // Show success message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Deleted!",
          text: "Project has been deleted successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Project deleted successfully",
        });
      } catch (error: any) {
        // Show error message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: "Failed to delete project. Please try again.",
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(error);
      }
    }
  }, [deleteProject, toast]);

  const handleRestoreProject = useCallback(async (project: Project) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Restore ${project.name}?`,
      text: "Are you sure you want to restore this project?",
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
        text: 'Please wait while we restore the project.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await restoreProject(project._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Restored!",
          text: "Project has been restored successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Project restored successfully.",
          variant: "default",
        });

        fetchProjects();
      } catch (error: any) {
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: error.error?.message || error.error || error.message || "Failed to restore project. Please try again.",
          icon: "error",
          confirmButtonText: "OK"
        });
        handleAPIError(error, "Failed to restore project. Please try again.");
      }
    }
  }, [restoreProject, toast, fetchProjects]);

  const handleApproveProject = useCallback(async (project: Project) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: "Approve Project?",
      text: `Are you sure you want to approve "${project.name}"?`,
      icon: "question",
      showCancelButton: true,
      confirmButtonColor: "#16a34a",
      cancelButtonColor: "#6b7280",
      confirmButtonText: "Yes, approve it!",
      cancelButtonText: "Cancel",
    });

    if (result.isConfirmed) {
      // Show loading with SweetAlert's built-in loader
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Approving...',
        text: 'Please wait while we approve the project.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await approveProjectFn(project._id!);

        // Show success message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Approved!",
          text: "Project has been approved successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Project approved successfully",
        });
      } catch (error: any) {
        // Show error message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: "Failed to approve project. Please try again.",
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(error);
      }
    }
  }, [approveProjectFn, toast]);


  // Clear error effect
  useEffect(() => {
    if (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: error,
      });
      clearError();
    }
  }, [error, toast, clearError]);



  // Stats display - Primary stats only (5 cards)
  const statsCards = useMemo(() => {
    if (!stats) return [];

    return [
      {
        title: "Total",
        value: stats.totalProjects || 0,
        icon: <FolderOpen className="h-4 w-4" />,
        color: "text-muted-foreground"
      },
      {
        title: "Active",
        value: stats.activeProjects || 0,
        icon: <div className="h-3 w-3 bg-blue-600 rounded-full" />,
        color: "text-blue-600"
      },
      {
        title: "Pending",
        value: stats.pendingProjects || 0,
        icon: <div className="h-3 w-3 bg-green-600 rounded-full" />,
        color: "text-green-600"
      },
      {
        title: "Avg Budget",
        value: stats.averageBudget ? formatCurrency(stats.averageBudget) : '$0',
        icon: <DollarSign className="h-4 w-4" />,
        color: "text-purple-600"
      },
      {
        title: "High Priority",
        value: stats.highPriorityProjects || 0,
        icon: <AlertTriangle className="h-4 w-4" />,
        color: "text-orange-600"
      },
    ];
  }, [stats]);


  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        subtitle="Manage client projects and track their progress"
        onAddClick={() => navigateTo("/projects/add")}
        addButtonText="Add Project"

        // Filter functionality
        showFilterButton={true}
        hasActiveFilters={Object.values(uiFilters).some(v => v && v !== 'all' && v !== '')}
        isFilterExpanded={isFilterExpanded}
        onFilterToggle={() => {
          setIsFilterExpanded(!isFilterExpanded);
        }}
        activeFiltersCount={Object.values(uiFilters).filter(v => v && v !== 'all' && v !== '').length}
        filterText="Filter Projects"

        // Refresh functionality
        showRefreshButton={true}
        onRefresh={() => {
          handleFilterReset();
          fetchProjects();
        }}
        isRefreshing={loading}
      >
        {/* Generic Filter */}
        {isFilterExpanded && (
          <GenericFilter
            config={filterConfig}
            values={uiFilters}
            onFilterChange={handleFilterChange}
            onReset={handleFilterReset}
            loading={loading}
            title="Filter Projects"
            className="bg-card"
          />
        )}
      </PageHeader>

      {error && (
        <Alert variant="destructive" className="border-destructive bg-destructive/10">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="text-destructive-foreground">{error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-4">
        <DataTable
          statsCards={statsCards}
          data={projects}
          columns={columns}
          loading={loading}
          NoOfCards={5}
          totalCount={pagination.total}
          pageSize={pagination.limit}
          currentPage={pagination.page}
          onPageChange={handlePageChange}
          onPageSizeChange={handlePageSizeChange}
          onSort={handleSort}
          sortColumn={sort.field}
          sortDirection={sort.direction}
          onDelete={handleDeleteProject}
          onRestore={handleRestoreProject}
          actions={{
            view: {
              enabled: true,
              label: "Quick View",
              onClick: (project: Project) => {
                setSelectedProject(project);
                setIsQuickViewOpen(true);
              },
            },
            edit: {
              enabled: true,
              label: "Edit",
              onClick: (project: Project) => {
                // Navigate to edit tab of project detail page
                if (typeof window !== 'undefined') {
                  localStorage.setItem('project-details-active-tab', 'edit');
                }
                navigateTo(`/projects/${project._id}`);
              },
            },
          }}
          enablePermissionChecking={true}
          emptyMessage="No projects found"

          customActions={[
            {
              label: "Project Details",
              onClick: (project: Project) => {
                // Navigate to edit tab of project detail page
                if (typeof window !== 'undefined') {
                  localStorage.setItem('project-details-active-tab', 'overview');
                }
                navigateTo(`/projects/${project._id}`);
              },
              variant: "default",
              icon: <FileText className="h-4 w-4" />, // Lucide icon for detail
              requiredPermission: {
                resource: "projects",
                action: "read",
              },
              hideIf: (project: Project) => (project as any).status === 'deleted',

            },
            {
              label: "Categorize",
              onClick: (project: Project) => {
                // Navigate to edit tab of project detail page
                if (typeof window !== 'undefined') {
                  localStorage.setItem('project-details-active-tab', 'categorization');
                }
                navigateTo(`/projects/${project._id}`);
              },
              variant: "default",
              icon: <FolderOpen className="h-4 w-4" />, // Lucide icon for categorization
              requiredPermission: {
                resource: "projects",
                action: "categorize",
              },
              hideIf: (project: Project) => (project as any).status === 'deleted',
            },
            {
              label: "Approve",
              onClick: (project: Project) => handleApproveProject(project),
              variant: "default",
              icon: <Users className="h-4 w-4" />,
              disabled: (project: Project) => project.status === 'approved',
              requiredPermission: {
                resource: "projects",
                action: "approve",
              },
              hideIf: (project: Project) => (project as any).status === 'deleted',
            },
          ]}
        />
      </div>

      {/* Quick View Modal */}
      <CustomModal
        isOpen={isQuickViewOpen}
        onClose={() => setIsQuickViewOpen(false)}
        title="Project Details"
        position="top-right"
        modalSize="lg"
      >
        {selectedProject && (
          <div className="space-y-4">
            {/* Tab Navigation */}
            <div className="border-b border-border">
              <nav className="flex" aria-label="Tabs">
                {[
                  { id: 'overview', name: 'Overview' },
                  { id: 'details', name: 'Details' },
                  { id: 'departments', name: 'Departments' }
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
                  {/* Project Header */}
                  <div className="flex items-start space-x-4">
                    <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                      <FolderOpen className="h-6 w-6 text-primary" />
                    </div>
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold">{selectedProject.name}</h3>
                      <p className="text-sm text-muted-foreground">{selectedProject.projectType || 'General Project'}</p>
                    </div>
                    <div className="flex gap-2">
                      <Badge variant={
                        selectedProject.status === 'active' ? 'default' :
                          selectedProject.status === 'completed' ? 'secondary' :
                            selectedProject.status === 'pending' ? 'outline' : 'destructive'
                      }>
                        {selectedProject.status}
                      </Badge>
                      <Badge variant={
                        selectedProject.priority === 'urgent' ? 'destructive' :
                          selectedProject.priority === 'high' ? 'secondary' :
                            selectedProject.priority === 'medium' ? 'default' : 'outline'
                      }>
                        {selectedProject.priority}
                      </Badge>
                    </div>
                  </div>

                  {/* Project Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Client</label>
                      <p className="mt-1">
                        {typeof selectedProject.client === 'object' && selectedProject.client
                          ? selectedProject.client.name
                          : selectedProject.client || 'Not specified'
                        }
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Budget</label>
                      <p className="mt-1">
                        {selectedProject.budget ? formatCurrency(selectedProject.budget) : 'Not set'}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Start Date</label>
                      <p className="mt-1">
                        {selectedProject.startDate
                          ? new Date(selectedProject.startDate).toLocaleDateString("en-US",{
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                          })
                          : 'Not set'
                        }
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">End Date</label>
                      <p className="mt-1">
                        {selectedProject.endDate
                          ? new Date(selectedProject.endDate).toLocaleDateString("en-US",{
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                          })
                          : 'Not set'
                        }
                      </p>
                    </div>
                  </div>

                  {/* Description */}
                  {selectedProject.description && (
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Description</label>
                      <HtmlTextRenderer
                        content={selectedProject.description}
                        fallbackText="No description"
                        showFallback={true}
                        renderAsHtml={true}
                        truncateHtml={false}
                      />
                    </div>
                  )}

                  {/* Created Info */}
                  <div className="pt-4 border-t">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <label className="text-muted-foreground">Created</label>
                        <p className="mt-1">
                          {selectedProject.createdAt
                            ? new Date(selectedProject.createdAt).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric'
                            })
                            : 'Unknown'
                          }
                        </p>
                      </div>
                      <div>
                        <label className="text-muted-foreground">Last Updated</label>
                        <p className="mt-1">
                          {selectedProject.updatedAt
                            ? new Date(selectedProject.updatedAt).toLocaleString("en-US", {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                            })
                            : 'Unknown'
                          }
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Details Tab */}
              {activeTab === 'details' && (
                <div className="space-y-4">
                  {selectedProject.requirements && (
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Requirements</label>
                      <div className="mt-2 p-3 bg-muted/50 rounded-lg">
                        <p className="text-sm whitespace-pre-wrap">{selectedProject.requirements}</p>
                      </div>
                    </div>
                  )}

                  {selectedProject.timeline && (
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Timeline</label>
                      <div className="mt-2 p-3 bg-muted/50 rounded-lg">
                        <p className="text-sm whitespace-pre-wrap">{selectedProject.timeline}</p>
                      </div>
                    </div>
                  )}

                  {!selectedProject.requirements && !selectedProject.timeline && (
                    <div className="text-center py-8">
                      <FileText className="h-12 w-12 mx-auto text-muted-foreground/50 mb-3" />
                      <p className="text-muted-foreground">No additional details available</p>
                    </div>
                  )}
                </div>
              )}

              {/* Departments Tab */}
              {activeTab === 'departments' && (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground mb-3 block">
                      Assigned Departments
                    </label>
                    {selectedProject.departmentTasks && selectedProject.departmentTasks.length > 0 ? (
                      <div className="space-y-3">
                        {selectedProject.departmentTasks
                          .map((dept) => (
                            <div key={dept.departmentId} className="border rounded-lg overflow-hidden">
                              {/* Department Header */}
                              <div className="flex items-center justify-between p-3 bg-muted/30">
                                <div className="flex items-center space-x-3">
                                  <Building2 className="h-4 w-4 text-primary" />
                                  <span className="font-medium">{dept.departmentName}</span>
                                </div>
                                <div className="flex items-center space-x-2">
                                  <Badge variant="secondary" className="text-xs">
                                    {dept.taskCount} Tasks
                                  </Badge>
                                  <Badge variant="outline">Assigned</Badge>
                                </div>
                              </div>

                              {/* Tasks List */}
                              {dept.tasks && dept.tasks.length > 0 && (
                                <div className="p-3 pt-0">
                                  <div className="space-y-2">
                                    {dept.tasks.map((task) => (
                                      <div key={task._id} className="flex items-center justify-between p-2 bg-background rounded border border-border/50">
                                        <div className="flex items-center space-x-2">
                                          <div className="w-2 h-2 rounded-full bg-muted-foreground/50"></div>
                                          <span className="text-sm font-medium">{task.title}</span>
                                        </div>
                                        <Badge
                                          variant={
                                            task.status === 'completed' ? 'secondary' :
                                              task.status === 'in_progress' ? 'default' :
                                                task.status === 'pending' ? 'outline' : 'destructive'
                                          }
                                          className="text-xs"
                                        >
                                          {task.status.replace('_', ' ')}
                                        </Badge>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* No tasks message */}
                              {(!dept.tasks || dept.tasks.length === 0) && (
                                <div className="p-3 text-center text-sm text-muted-foreground">
                                  No tasks assigned to this department yet
                                </div>
                              )}
                            </div>
                          ))}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Building2 className="h-12 w-12 mx-auto text-muted-foreground/50 mb-3" />
                        <p className="text-muted-foreground">No departments assigned</p>
                        <p className="text-sm text-muted-foreground mt-1">
                          This project hasn't been categorized yet
                        </p>
                      </div>
                    )}
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
              <Button
                onClick={() => {
                  setIsQuickViewOpen(false);
                  navigateTo(`/projects/edit/${selectedProject._id}`);
                }}
              >
                Edit Project
              </Button>
            </div>
          </div>
        )}
      </CustomModal>
    </div>
  );
}