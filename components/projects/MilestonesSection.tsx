"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import {
  Flag,
  Plus,
  Edit3,
  Trash2,
  Calendar,
  Target,
  Clock,
  User,
  CheckCircle,
  AlertCircle,
  TrendingUp,
  Link as LinkIcon,
  DollarSign,
  RefreshCw,
  Workflow,
  Send,
  FileText,
  BookTemplateIcon,
  Filter
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import CustomModal from "@/components/shared/custom-modal";
import GenericFilter, { FilterConfig } from "@/components/shared/generic-filter";
import { createMilestoneFormSchema, updateMilestoneFormSchema, getMilestoneStatusColor, getMilestonePriorityColor } from "@/lib/validations/milestone";
import type { CreateMilestoneFormData, UpdateMilestoneFormData } from "@/lib/validations/milestone";
import { useToast } from "@/hooks/use-toast";
import { useMilestoneManagement } from "@/hooks/use-milestones";
import { useUsers } from "@/hooks/use-users";
import { usePermissions } from "@/hooks/use-permissions";
import { formatDistanceToNow } from "date-fns";
import type { IMilestone } from "@/models/Milestone";
import { MilestoneTemplateGallery } from "./MilestoneTemplateGallery";
import { MilestoneApprovalManager } from "./MilestoneApprovalManager";
import {
  InlineMilestoneStatusDropdown,
  InlineMilestonePriorityDropdown,
  InlineMilestoneDueDateInput,
  InlineMilestoneProgressDisplay,
  getProgressFromStatus,
  milestoneStatusColors,
  milestonePriorityColors,
} from "./InlineMilestoneEditUtils";

interface MilestonesSectionProps {
  projectId: string;
  phaseId?: string;
  onMilestoneUpdate?: () => void;
}

export function MilestonesSection({ projectId, phaseId, onMilestoneUpdate }: MilestonesSectionProps) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingMilestone, setEditingMilestone] = useState<IMilestone | null>(null);
  const [showTemplateGallery, setShowTemplateGallery] = useState(false);
  const [showApprovalManager, setShowApprovalManager] = useState(false);
  const [submittingApproval, setSubmittingApproval] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [filterOpen, setFilterOpen] = useState(false);
  const filterButtonRef = React.useRef<HTMLButtonElement | null>(null);

  const { toast } = useToast();

  // Helper function to check if a specific milestone action is loading
  const isActionLoadingForMilestone = (milestoneId: string) => {
    return actionLoading[milestoneId] || false;
  };
  const { canCreate, canUpdate, canDelete } = usePermissions();
  const { users } = useUsers();

  // Use milestone management hook FIRST (before callbacks that depend on it)
  const {
    milestones,
    loading,
    error,
    refetch,
    createMilestone,
    updateMilestone,
    deleteMilestone,
    updateMilestoneStatus,
    updateMilestoneDueDate,
    isMilestoneLoading,
    individualLoading,
    completedMilestones,
    pendingMilestones,
    inProgressMilestones,
    overdueMilestones,
    overallProgress,
    completionRate,
    setFilters: setBackendFilters,
    filters: backendFilters,
  } = useMilestoneManagement(projectId, phaseId);

  // Milestone filter configuration
  const milestoneFilterConfig: FilterConfig = useMemo(() => ({
    fields: [
      { key: 'search', label: 'Search', type: 'text', placeholder: 'Search milestone title or description', cols: 12 },
      {
        key: 'status', label: 'Status', type: 'select', placeholder: 'All', options: [
          { value: 'all', label: 'All' },
          { value: 'pending', label: 'Pending' },
          { value: 'in-progress', label: 'In Progress' },
          { value: 'completed', label: 'Completed' },
          { value: 'cancelled', label: 'Cancelled' },
        ], cols: 6
      },
      {
        key: 'priority', label: 'Priority', type: 'select', placeholder: 'All', options: [
          { value: 'all', label: 'All' },
          { value: 'low', label: 'Low' },
          { value: 'medium', label: 'Medium' },
          { value: 'high', label: 'High' },
          { value: 'urgent', label: 'Urgent' },
        ], cols: 6
      },
      { 
        key: 'assigneeId', 
        label: 'Assignee', 
        type: 'select', 
        placeholder: 'Any', 
        options: [
          { value: 'all', label: 'Any' }, 
          ...(users || []).filter((u: any) => u.status === 'active').map((u: any) => ({ value: u._id, label: u.name }))
        ], 
        searchable: true, 
        cols: 12 
      },
      { key: 'dueDateFrom', label: 'Due Date From', type: 'date', cols: 6 },
      { key: 'dueDateTo', label: 'Due Date To', type: 'date', cols: 6 },
    ],
    defaultValues: { search: '', status: 'all', priority: 'all', assigneeId: 'all', dueDateFrom: '', dueDateTo: '' }
  }), [users]);

  // Apply filters function - uses backend filtering for supported fields
  const applyFilters = useCallback((values: any) => {
    // Build backend filter object for API query
    const mapped: any = {
      projectId, // Always filter by project
    };
    
    // Add phaseId if provided
    if (phaseId) {
      mapped.phaseId = phaseId;
    }
    
    // Map filters following task pattern
    if (values.search) mapped.search = values.search;
    if (values.status && values.status !== 'all') mapped.status = values.status;
    if (values.priority && values.priority !== 'all') mapped.priority = values.priority;
    if (values.assigneeId && values.assigneeId !== 'all') mapped.assigneeId = values.assigneeId;
    if (values.dueDateFrom) mapped.dueDateFrom = values.dueDateFrom;
    if (values.dueDateTo) mapped.dueDateTo = values.dueDateTo;
    
    // Apply backend filters
    setBackendFilters(mapped);
  }, [projectId, phaseId, setBackendFilters]);

  // Compute number of applied filters (ignore defaults and projectId/phaseId)
  const filterCount = useMemo(() => {
    const keys = ['search', 'status', 'priority', 'assigneeId', 'dueDateFrom', 'dueDateTo'];
    if (!backendFilters) return 0;
    return keys.reduce((count, k) => {
      const v = (backendFilters as any)[k];
      if (v === undefined || v === null) return count;
      if (v === '' || v === 'all') return count;
      return count + 1;
    }, 0);
  }, [backendFilters]);

  // Forms
  const addForm = useForm<CreateMilestoneFormData>({
    resolver: zodResolver(createMilestoneFormSchema),
    defaultValues: {
      title: "",
      description: "",
      projectId,
      phaseId: phaseId || "",
      dueDate: "",
      priority: "medium",
      status: "pending",
      assigneeId: "",
      deliverables: [],
      successCriteria: [],
      budgetAllocation: 0,
    },
  });

  const editForm = useForm<UpdateMilestoneFormData>({
    resolver: zodResolver(updateMilestoneFormSchema),
    defaultValues: {
      title: "",
      description: "",
      dueDate: "",
      priority: "medium",
      status: "pending",
      assigneeId: "",
      deliverables: [],
      successCriteria: [],
      budgetAllocation: 0,
    },
  });



  // Filter milestones based on advanced filters (search is client-side only)
  const filteredMilestones = useMemo(() => {
    let filtered = [...(milestones || [])];

    // Search filter (client-side only)
    const searchValue = (backendFilters as any)?.search || '';
    if (searchValue && searchValue.trim() !== '') {
      const searchLower = searchValue.toLowerCase();
      filtered = filtered.filter((milestone: IMilestone) =>
        milestone.title.toLowerCase().includes(searchLower) ||
        (milestone.description && milestone.description.toLowerCase().includes(searchLower))
      );
    }

    return filtered;
  }, [milestones, backendFilters]);

  // Calculate statistics
  const milestoneStats = {
    total: (milestones || []).length,
    completed: (milestones || []).filter((m: IMilestone) => m.status === 'completed').length,
    inProgress: (milestones || []).filter((m: IMilestone) => m.status === 'in-progress').length,
    overdue: (milestones || []).filter((m: IMilestone) => m.status === 'overdue').length,
    totalBudget: (milestones || []).reduce((sum: number, m: IMilestone) => sum + (m.budgetAllocation || 0), 0),
    actualCost: (milestones || []).reduce((sum: number, m: IMilestone) => sum + (m.actualCost || 0), 0),
    averageProgress: Math.round((milestones || []).reduce((sum: number, m: IMilestone) => sum + (m.progress || 0), 0) / ((milestones || []).length || 1)) || 0,
  };

  // Handle milestone creation
  const handleAddMilestone = async (data: CreateMilestoneFormData) => {
    try {
      await createMilestone({
        title: data.title,
        description: data.description || "",
        projectId: projectId,
        phaseId: phaseId || "",
        dueDate: new Date(data.dueDate),
        priority: data.priority,
        status: data.status || "pending",
        progress: 0, // Always start at 0, will be calculated from status
        assigneeId: data.assigneeId || "",
        deliverables: data.deliverables,
        successCriteria: data.successCriteria,
        budgetAllocation: data.budgetAllocation ? Number(data.budgetAllocation) : undefined,
        linkedTaskIds: [],
        dependencies: [],
      });

      // Ensure data is refreshed
      await refetch();
      
      setShowAddModal(false);
      addForm.reset();
      onMilestoneUpdate?.();
    } catch (error) {
      console.error('Error creating milestone:', error);
    }
  };

  // Handle milestone editing
  const handleEditMilestone = (milestone: IMilestone) => {
    setEditingMilestone(milestone);
    editForm.reset({
      title: milestone.title,
      description: milestone.description,
      dueDate: new Date(milestone.dueDate).toISOString().split('T')[0],
      priority: milestone.priority,
      status: milestone.status,
      assigneeId: milestone.assigneeId?.toString(),
      deliverables: milestone.deliverables,
      successCriteria: milestone.successCriteria,
      budgetAllocation: milestone.budgetAllocation,
    });
  };

  // Inline update handlers with optimistic updates
  const handleInlineStatusChange = async (milestoneId: string, newStatus: string) => {
    try {
      await updateMilestoneStatus(milestoneId, newStatus as 'pending' | 'in-progress' | 'completed' | 'overdue');
      onMilestoneUpdate?.();
      
      toast({
        title: "Status Updated",
        description: `Milestone status changed to ${newStatus}`,
      });
    } catch (error: any) {
      toast({
        title: "Update Failed",
        description: error.message || "Failed to update milestone status",
        variant: "destructive",
      });
    }
  };

  const handleInlinePriorityChange = async (milestoneId: string, newPriority: string) => {
    try {
      await updateMilestone(milestoneId, { priority: newPriority as any });
      onMilestoneUpdate?.();
      
      toast({
        title: "Priority Updated",
        description: "Milestone priority has been updated",
      });
    } catch (error: any) {
      toast({
        title: "Update Failed",
        description: error.message || "Failed to update milestone priority",
        variant: "destructive",
      });
    }
  };

  const handleInlineDueDateChange = async (milestoneId: string, newDueDate: string) => {
    try {
      await updateMilestoneDueDate(milestoneId, newDueDate);
      onMilestoneUpdate?.();
      
      toast({
        title: "Due Date Updated",
        description: "Milestone due date has been updated",
      });
    } catch (error: any) {
      toast({
        title: "Update Failed",
        description: error.message || "Failed to update milestone due date",
        variant: "destructive",
      });
    }
  };

  const handleInlineProgressChange = async (milestoneId: string, newProgress: number) => {
    setActionLoading(prev => ({ ...prev, [milestoneId]: true }));
    try {
      await updateMilestone(milestoneId, { progress: newProgress });
      onMilestoneUpdate?.();
    } catch (error) {
      console.error('Error updating milestone progress:', error);
      toast({
        title: "Error",
        description: "Failed to update milestone progress",
        variant: "destructive",
      });
      throw error;
    } finally {
      setActionLoading(prev => ({ ...prev, [milestoneId]: false }));
    }
  };

  // Handle milestone update
  const handleUpdateMilestone = async (data: UpdateMilestoneFormData) => {
    if (!editingMilestone) return;

    try {
      await updateMilestone(editingMilestone._id, {
        title: data.title,
        description: data.description,
        dueDate: data.dueDate ? new Date(data.dueDate) : undefined,
        priority: data.priority,
        status: data.status,
        assigneeId: data.assigneeId,
        deliverables: data.deliverables,
        successCriteria: data.successCriteria,
        budgetAllocation: data.budgetAllocation ? parseFloat(data.budgetAllocation.toString()) : 0,
      });

      // Ensure data is refreshed
      await refetch();
      
      setEditingMilestone(null);
      editForm.reset();
      onMilestoneUpdate?.();
    } catch (error) {
      console.error('Error updating milestone:', error);
    }
  };

  // Handle template application
  const handleTemplateApply = async (result: any) => {
    toast({
      title: "Template Applied",
      description: `Successfully created ${result.milestones?.length || 0} milestones from template.`,
    });
    
    // Force refresh milestone data
    try {
      await refetch();
      onMilestoneUpdate?.();
    } catch (error) {
      console.error('Error refreshing milestones:', error);
      // Fallback: reload the page if refetch fails
      window.location.reload();
    }
  };

  // Submit milestone for approval
  const handleSubmitApproval = async (milestoneId: string) => {
    try {
      setSubmittingApproval(milestoneId);
      
      // Default approval workflow configuration
      const workflowConfig = {
        requiresApproval: true,
        approvalStages: [
          {
            stageName: "Manager Review",
            requiredRoles: ["project-manager", "department-head"],
            isOptional: false,
            order: 0
          },
          {
            stageName: "Final Approval",
            requiredRoles: ["super-administrator"],
            isOptional: false,
            order: 1
          }
        ]
      };

      const response = await fetch('/api/milestone-approvals', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          milestoneId,
          projectId,
          phaseId,
          workflowConfig,
          submissionComments: 'Milestone ready for approval',
          completionDeadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days from now
        })
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || 'Failed to submit milestone for approval');
      }

      toast({
        title: "Approval Submitted",
        description: "Milestone has been submitted for approval.",
      });

      refetch();
    } catch (error: any) {
      console.error('Error submitting approval:', error);
      toast({
        title: "Error",
        description: error.message || 'Failed to submit milestone for approval',
        variant: "destructive",
      });
    } finally {
      setSubmittingApproval(null);
    }
  };

  // Handle milestone deletion
  const handleDeleteMilestone = async (milestoneId: string) => {
    try {
      await deleteMilestone(milestoneId);
      
      // Ensure data is refreshed
      await refetch();
      onMilestoneUpdate?.();
    } catch (error) {
      console.error('Error deleting milestone:', error);
    }
  };

  // Handle milestone approval submission
  const handleSubmitForApproval = async (milestoneId: string) => {
    setSubmittingApproval(milestoneId);
    try {
      const milestone = milestones?.find(m => m._id === milestoneId);
      if (!milestone) return;

      // Submit milestone for approval with default workflow
      const response = await fetch('/api/milestone-approvals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          milestoneId,
          projectId,
          phaseId: phaseId || undefined,
          workflowConfig: {
            requiresApproval: true,
            approvalStages: [
              {
                stageName: 'Manager Review',
                requiredRoles: ['project-manager', 'admin'],
                isOptional: false,
                order: 1
              },
              {
                stageName: 'Client Approval',
                requiredRoles: ['client', 'admin'], 
                isOptional: false,
                order: 2
              }
            ]
          },
          submissionComments: `Milestone "${milestone.title}" submitted for approval`,
          completionDeadline: milestone.dueDate ? new Date(milestone.dueDate).toISOString() : undefined
        })
      });

      if (!response.ok) {
        throw new Error('Failed to submit milestone for approval');
      }

      toast({
        title: "Approval Submitted",
        description: `Milestone "${milestone.title}" has been submitted for approval`,
      });

      // Refresh data to show updated approval status
      refetch();
      onMilestoneUpdate?.();
    } catch (error) {
      console.error('Error submitting milestone for approval:', error);
      toast({
        title: "Error",
        description: "Failed to submit milestone for approval",
        variant: "destructive",
      });
    } finally {
      setSubmittingApproval(null);
    }
  };

  // Show loading only for initial load, not for updates
  if (loading && (!milestones || milestones.length === 0)) {
    return (
      <div className="flex items-center justify-center h-64 gap-2">
        <RefreshCw className="h-6 w-6 animate-spin text-primary" />
        <span>Loading Project Milestones...</span>
      </div>
    );
  }
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flag className="h-5 w-5 text-primary" />
            <CardTitle className="text-lg">Project Milestones</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <Button
              ref={filterButtonRef}
              variant="outline"
              size="sm"
              onClick={() => setFilterOpen(!filterOpen)}
              className="relative"
            >
              <Filter className="h-4 w-4 mr-1" />
              Filters
              {filterCount > 0 && (
                <Badge variant="destructive" className="ml-1 px-1 py-0 h-4 text-xs">
                  {filterCount}
                </Badge>
              )}
            </Button>
            
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setShowApprovalManager(true)}
            >
              <Workflow className="h-4 w-4 mr-1" />
              Approvals
            </Button>
            
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setShowTemplateGallery(true)}
            >
              <BookTemplateIcon className="h-4 w-4 mr-1" />
              Templates
            </Button>
            
            {canCreate("milestones") && (
              <Button onClick={() => setShowAddModal(true)} size="sm">
                <Plus className="h-4 w-4 mr-1" />
                Add Milestone
              </Button>
            )}
          </div>
        </div>

        {/* Milestone Filters */}
        <div className="mt-3">
          {filterOpen && (
            <GenericFilter
              config={milestoneFilterConfig}
              values={{
                search: (backendFilters?.search || '') as string,
                status: ((backendFilters as any)?.status || 'all') as string,
                priority: ((backendFilters as any)?.priority || 'all') as string,
                assigneeId: ((backendFilters as any)?.assigneeId || 'all') as string,
                dueDateFrom: ((backendFilters as any)?.dueDateFrom || '') as string,
                dueDateTo: ((backendFilters as any)?.dueDateTo || '') as string
              }}
              onFilterChange={applyFilters}
              onReset={() => {
                // Reset backend filters - explicitly clear all fields
                const resetFilters: any = {
                  projectId,
                  search: '',
                  status: '',
                  priority: '',
                  assigneeId: '',
                  dueDateFrom: '',
                  dueDateTo: ''
                };
                if (phaseId) resetFilters.phaseId = phaseId;
                setBackendFilters(resetFilters);
                // Trigger refetch to get all data
                setTimeout(() => refetch(), 100);
              }}
              presentation="dropdown"
              isOpen={filterOpen}
              onOpenChange={setFilterOpen}
              anchorRef={filterButtonRef}
              loading={loading}
            />
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Statistics Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-3 bg-muted rounded-lg">
            <div className="text-2xl font-bold text-primary">{milestoneStats.total}</div>
            <div className="text-sm text-muted-foreground">Total</div>
          </div>
          <div className="text-center p-3 bg-emerald-50 dark:bg-emerald-900/20 rounded-lg">
            <div className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">{milestoneStats.completed}</div>
            <div className="text-sm text-muted-foreground">Completed</div>
          </div>
          <div className="text-center p-3 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
            <div className="text-2xl font-bold text-amber-600 dark:text-amber-400">{milestoneStats.inProgress}</div>
            <div className="text-sm text-muted-foreground">In Progress</div>
          </div>
          <div className="text-center p-3 bg-destructive/10 rounded-lg">
            <div className="text-2xl font-bold text-destructive">{milestoneStats.overdue}</div>
            <div className="text-sm text-muted-foreground">Overdue</div>
          </div>
        </div>

        {/* Overall Progress */}
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-sm font-medium">Overall Progress</span>
            <span className="text-sm text-muted-foreground">{milestoneStats.averageProgress}%</span>
          </div>
          <Progress value={milestoneStats.averageProgress} className="h-2" />
        </div>

        <Separator />

        {/* Milestones List */}
        {filteredMilestones?.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Flag className="h-12 w-12 mx-auto mb-3 opacity-50" />
            {filterCount > 0 ? (
              <>
                <p>No milestones match your filters</p>
                <p className="text-sm">Try adjusting your filter criteria</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    // Reset backend filters - explicitly clear all fields
                    const resetFilters: any = {
                      projectId,
                      search: '',
                      status: '',
                      priority: '',
                      assigneeId: '',
                      dueDateFrom: '',
                      dueDateTo: ''
                    };
                    if (phaseId) resetFilters.phaseId = phaseId;
                    setBackendFilters(resetFilters);
                    // Trigger refetch to get all data
                    setTimeout(() => refetch(), 100);
                  }}
                  className="mt-4"
                >
                  Clear All Filters
                </Button>
              </>
            ) : (
              <>
                <p>No milestones found</p>
                <p className="text-sm">Create your first milestone to track project progress!</p>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            {/* Show loading indicator for bulk operations */}
            {loading && milestones && milestones.length > 0 && (
              <div className="flex items-center justify-center py-2 text-muted-foreground bg-muted/30 rounded-lg">
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                <span className="text-sm">Syncing milestones...</span>
              </div>
            )}
            {filteredMilestones.map((milestone: IMilestone) => (
              <Card key={milestone._id} className="border-l-4 border-l-primary/30 hover:shadow-md transition-shadow group">
                <CardContent className="pt-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      {/* Milestone Header */}
                      <div className="flex items-center gap-3 mb-2">
                        <div className={`w-3 h-3 rounded-full ${milestone.status === 'completed' ? 'bg-emerald-500' :
                            milestone.status === 'in-progress' ? 'bg-primary' :
                              milestone.status === 'overdue' ? 'bg-destructive' :
                                'bg-muted-foreground/30'
                          }`} />
                        <h4 className="font-semibold text-foreground truncate">{milestone.title}</h4>
                        <div className="flex gap-2 flex-shrink-0">
                          <InlineMilestoneStatusDropdown
                            milestone={milestone}
                            isLoading={isActionLoadingForMilestone(milestone._id)}
                            canUpdate={canUpdate("milestones")}
                            onStatusChange={handleInlineStatusChange}
                            isMilestoneLoading={isMilestoneLoading}
                          />
                          <InlineMilestonePriorityDropdown
                            milestone={milestone}
                            isLoading={isActionLoadingForMilestone(milestone._id)}
                            canUpdate={canUpdate("milestones")}
                            onPriorityChange={handleInlinePriorityChange}
                            isMilestoneLoading={isMilestoneLoading}
                          />
                        </div>
                      </div>

                      {milestone.description && (
                        <p className="text-sm text-muted-foreground mb-3">
                          {milestone.description}
                        </p>
                      )}

                      {/* Progress Bar */}
                      <div className="mb-3">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-xs text-muted-foreground">Progress (Auto-calculated)</span>
                          <InlineMilestoneProgressDisplay
                            milestone={milestone}
                            isLoading={isActionLoadingForMilestone(milestone._id)}
                          />
                        </div>
                        <Progress value={getProgressFromStatus(milestone.status)} className="h-2" />
                      </div>

                      {/* Milestone Metadata */}
                      <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                        <div className="flex items-center gap-1">
                          <InlineMilestoneDueDateInput
                            milestone={milestone}
                            isLoading={isActionLoadingForMilestone(milestone._id)}
                            canUpdate={canUpdate("milestones")}
                            onDueDateChange={handleInlineDueDateChange}
                            isMilestoneLoading={isMilestoneLoading}
                          />
                          {milestone.status === 'overdue' && (
                            <span className="text-destructive font-medium text-xs">
                              (Overdue)
                            </span>
                          )}
                        </div>
                        {milestone.assigneeId && (
                          <span className="flex items-center gap-1">
                            <User className="h-3 w-3" />
                            Assigned
                          </span>
                        )}
                        {milestone.linkedTaskIds && milestone.linkedTaskIds.length > 0 && (
                          <span className="flex items-center gap-1">
                            <LinkIcon className="h-3 w-3" />
                            {milestone.linkedTaskIds.length} linked tasks
                          </span>
                        )}
                        {milestone.budgetAllocation && (
                          <span className="flex items-center gap-1">
                            <DollarSign className="h-3 w-3" />
                            Budget: ${milestone.budgetAllocation.toLocaleString()}
                            {milestone.actualCost && (
                              <span className={milestone.actualCost > milestone.budgetAllocation ? 'text-destructive' : 'text-emerald-600'}>
                                / ${milestone.actualCost.toLocaleString()}
                              </span>
                            )}
                          </span>
                        )}
                      </div>

                      {/* Deliverables Preview */}
                      {milestone.deliverables && milestone.deliverables.length > 0 && (
                        <div className="mt-3">
                          <div className="text-xs text-muted-foreground mb-1">Deliverables:</div>
                          <div className="flex flex-wrap gap-1">
                            {milestone.deliverables.slice(0, 3).map((deliverable: string, index: number) => (
                              <Badge key={index} variant="secondary" className="text-xs">
                                {deliverable}
                              </Badge>
                            ))}
                            {milestone.deliverables.length > 3 && (
                              <Badge variant="secondary" className="text-xs">
                                +{milestone.deliverables.length - 3} more
                              </Badge>
                            )}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Milestone Actions */}
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <Target className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {milestone.status === 'in-progress' && canUpdate("milestones") && (
                          <DropdownMenuItem 
                            onClick={() => handleSubmitApproval(milestone._id)}
                            disabled={submittingApproval === milestone._id}
                          >
                            <Send className="h-4 w-4 mr-2" />
                            Submit for Approval
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuItem onClick={() => handleEditMilestone(milestone)}>
                          <Edit3 className="h-4 w-4 mr-2" />
                          Edit Milestone
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleDeleteMilestone(milestone._id)}
                          className="text-destructive"
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete Milestone
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Add Milestone Modal */}
        <CustomModal
          isOpen={showAddModal}
          onClose={() => setShowAddModal(false)}
          title="Create New Milestone"
          modalSize="lg"
        >
          <form onSubmit={addForm.handleSubmit(handleAddMilestone)} className="space-y-4">
            <div>
              <Label htmlFor="title">Milestone Title</Label>
              <Input
                id="title"
                {...addForm.register("title")}
                placeholder="Enter milestone title"
              />
              {addForm.formState.errors.title && (
                <p className="text-sm text-destructive mt-1">
                  {addForm.formState.errors.title.message}
                </p>
              )}
            </div>

            <div>
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                {...addForm.register("description")}
                placeholder="Describe the milestone objectives..."
                rows={3}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="dueDate">Due Date</Label>
                <Input
                  id="dueDate"
                  type="date"
                  {...addForm.register("dueDate")}
                />
                {addForm.formState.errors.dueDate && (
                  <p className="text-sm text-destructive mt-1">
                    {addForm.formState.errors.dueDate.message}
                  </p>
                )}
              </div>

              <div>
                <Label htmlFor="priority">Priority</Label>
                <Select onValueChange={(value) => addForm.setValue("priority", value as any)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select priority" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="urgent">Urgent</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="status">Status</Label>
                <Select onValueChange={(value) => addForm.setValue("status", value as any)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="in-progress">In Progress</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="on-hold">On Hold</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="progress">Progress (%)</Label>
                <Input
                  id="progress"
                  type="number"
                  min="0"
                  max="100"
                  {...addForm.register("progress", { valueAsNumber: true })}
                  placeholder="0"
                />
              </div>
            </div>

            <div>
              <Label htmlFor="budgetAllocation">Budget Allocation (Optional)</Label>
              <Input
                id="budgetAllocation"
                type="number"
                {...addForm.register("budgetAllocation")}
                placeholder="Enter budget amount"
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setShowAddModal(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={loading}>
                {loading ? "Creating..." : "Create Milestone"}
              </Button>
            </div>
          </form>
        </CustomModal>

        {/* Edit Milestone Modal */}
        <CustomModal
          isOpen={!!editingMilestone}
          onClose={() => setEditingMilestone(null)}
          title="Edit Milestone"
        >
          <form onSubmit={editForm.handleSubmit(handleUpdateMilestone)} className="space-y-4">
            <div>
              <Label htmlFor="editTitle">Milestone Title</Label>
              <Input
                id="editTitle"
                {...editForm.register("title")}
                placeholder="Enter milestone title"
              />
            </div>

            <div>
              <Label htmlFor="editDescription">Description</Label>
              <Textarea
                id="editDescription"
                {...editForm.register("description")}
                placeholder="Describe the milestone objectives..."
                rows={3}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="editDueDate">Due Date</Label>
                <Input
                  id="editDueDate"
                  type="date"
                  {...editForm.register("dueDate")}
                />
              </div>

              <div>
                <Label htmlFor="editPriority">Priority</Label>
                <Select onValueChange={(value) => editForm.setValue("priority", value as any)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select priority" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="urgent">Urgent</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="editStatus">Status</Label>
                <Select onValueChange={(value) => editForm.setValue("status", value as any)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="in-progress">In Progress</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="on-hold">On Hold</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="editProgress">Progress (%)</Label>
                <Input
                  id="editProgress"
                  type="number"
                  min="0"
                  max="100"
                  {...editForm.register("progress", { valueAsNumber: true })}
                  placeholder="0"
                />
              </div>
            </div>

            <div>
              <Label htmlFor="editBudgetAllocation">Budget Allocation</Label>
              <Input
                id="editBudgetAllocation"
                type="number"
                {...editForm.register("budgetAllocation")}
                placeholder="Enter budget amount"
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditingMilestone(null)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={loading}>
                {loading ? "Updating..." : "Update Milestone"}
              </Button>
            </div>
          </form>
        </CustomModal>

        {/* Template Gallery Modal */}
        <MilestoneTemplateGallery
          isOpen={showTemplateGallery}
          onClose={() => setShowTemplateGallery(false)}
          projectId={projectId}
          phaseId={phaseId}
          onApplyTemplate={handleTemplateApply}
        />
        
        {/* Approval Manager Modal */}
        <CustomModal
          isOpen={showApprovalManager}
          onClose={() => setShowApprovalManager(false)}
          title="Milestone Approval Management"
          modalSize="xl"
        >
          <div className="overflow-auto max-h-[calc(90vh-8rem)]">
            <MilestoneApprovalManager
              projectId={projectId}
              onApprovalUpdate={() => {
                refetch();
                onMilestoneUpdate?.();
              }}
            />
          </div>
        </CustomModal>
      </CardContent>
    </Card>
  );
}