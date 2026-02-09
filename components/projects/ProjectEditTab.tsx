"use client";

import React, { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import GenericForm from '@/components/shared/generic-form';
import type { SubFormConfig } from '@/components/shared/generic-form';
import { useToast } from '@/hooks/use-toast';
import { useClients } from '@/hooks/use-clients';
import { useDepartments } from '@/hooks/use-departments';
import { useUsers } from '@/hooks/use-users';
import { useProject } from '@/hooks/use-projects';
import { updateProjectFormSchema, UpdateProjectFormData } from '@/lib/validations/project';
import { Save } from 'lucide-react';

interface ProjectEditTabProps {
  project: any;
  onProjectUpdate?: () => void;
}

export function ProjectEditTab({ project, onProjectUpdate }: ProjectEditTabProps) {
  const [loading, setLoading] = useState(false);
  // Use actionLoading from the hook in addition to local loading state
  const { toast } = useToast();
  const { clients } = useClients();
  const { updateProject, actionLoading } = useProject();

  const form = useForm<UpdateProjectFormData>({
    resolver: zodResolver(updateProjectFormSchema),
    mode: 'onChange', // Enable real-time validation
    defaultValues: {
      name: "",
      description: "",
      clientId: "",
      requirements: [],
      customerServices: [],
      projectType: "",
      complexity: "",
      timeline: "",
      budget: undefined,
      startDate: "",
      endDate: "",
      status: "pending",
      priority: "medium",
      departmentIds: [],
      // Enhanced professional CRM fields
      budgetBreakdown: {
        development: undefined,
        design: undefined,
        testing: undefined,
        deployment: undefined,
        maintenance: undefined,
        contingency: undefined,
      },
      risks: [],
      resources: {
        estimatedHours: undefined,
        actualHours: undefined,
        tools: [],
        externalResources: [],
      },
    },
  });

  // Update form when project data changes
  useEffect(() => {
    if (project) {

      form.reset({
        name: project.name,
        description: project.description || "",
        clientId: project.clientId,
        requirements: project.requirements || [],
        customerServices: project.customerServices || [],
        projectType: project.projectType || "",
        complexity: project.complexity || "",
        timeline: project.timeline || "",
        budget: project.budget || 0,
        startDate: project.startDate ? new Date(project.startDate).toISOString().split('T')[0] : "",
        endDate: project.endDate ? new Date(project.endDate).toISOString().split('T')[0] : "",
        status: project.status,
        priority: project.priority,
        departmentIds: project.departmentIds || [],

        // Enhanced professional CRM fields
        budgetBreakdown: project.budgetBreakdown ? {
          development: project.budgetBreakdown.development || undefined,
          design: project.budgetBreakdown.design || undefined,
          testing: project.budgetBreakdown.testing || undefined,
          deployment: project.budgetBreakdown.deployment || undefined,
          maintenance: project.budgetBreakdown.maintenance || undefined,
          contingency: project.budgetBreakdown.contingency || undefined,
        } : {
          development: undefined,
          design: undefined,
          testing: undefined,
          deployment: undefined,
          maintenance: undefined,
          contingency: undefined,
        },
        risks: project.risks || [],
        resources: project.resources ? {
          estimatedHours: project.resources.estimatedHours || undefined,
          actualHours: project.resources.actualHours || undefined,
          tools: project.resources.tools || [],
          externalResources: project.resources.externalResources || [],
        } : {
          estimatedHours: undefined,
          actualHours: undefined,
          tools: [],
          externalResources: [],
        },

      });
    }
  }, [project, form]);

  const handleSubmit = async (data: UpdateProjectFormData) => {
    console.log('🚀 Form submission started with data:', data);
    console.log('🔍 Form validation state:', {
      isValid: form.formState.isValid,
      errors: form.formState.errors,
      isDirty: form.formState.isDirty,
      isSubmitting: form.formState.isSubmitting
    });
    setLoading(true);
    try {
      // Validate that at least one field is provided for update
      const hasData = Object.entries(data).some(([key, value]) => {
        if (value === null || value === undefined || value === '') return false;
        if (typeof value === 'object' && !Array.isArray(value)) {
          return Object.values(value).some(v => {
            if (Array.isArray(v)) return v.length > 0;
            if (typeof v === 'number') return true;
            return v !== null && v !== undefined && v !== '';
          });
        }
        if (Array.isArray(value)) {
          return true; // Empty arrays are valid updates (user might want to clear all items)
        }
        return true;
      });

      if (!hasData) {
        toast({
          variant: "destructive",
          title: "Validation Error",
          description: "Please modify at least one field before submitting",
        });
        return;
      }

      // Convert form data to proper API format (strings to numbers, dates, etc.)
      const apiData: any = { ...data };

      // Budget and budgetBreakdown are now handled by schema transformation

      // Resources are now handled by schema transformation

      // Convert start and end dates
      if (apiData.startDate && apiData.startDate.trim() !== '') {
        apiData.startDate = new Date(apiData.startDate);
      } else {
        apiData.startDate = undefined;
      }

      if (apiData.endDate && apiData.endDate.trim() !== '') {
        apiData.endDate = new Date(apiData.endDate);
      } else {
        apiData.endDate = undefined;
      }

      // Use the existing project update hook following the same pattern as other CRUD operations
      await updateProject(project._id, apiData);

      toast({
        title: "Success",
        description: "Project updated successfully",
      });

      // Reset form to mark as pristine after successful update
      form.reset(data);
      onProjectUpdate?.();
    } catch (error: any) {
      console.error('Error updating project:', error);

      // Handle validation errors specifically
      if (error.message.includes('validation') || error.message.includes('required')) {
        toast({
          variant: "destructive",
          title: "Validation Error",
          description: error.message,
        });
      } else {
        toast({
          variant: "destructive",
          title: "Error",
          description: error.message || "Failed to update project",
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const formFields: SubFormConfig[] = [
    {
      subform_title: "Basic Information",
      fields: [
        {
          name: "name",
          label: "Project Name",
          type: "text" as const,
          placeholder: "Enter project name",
          required: true,
          description: "A clear, descriptive name for the project",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "status",
          label: "Status",
          type: "select" as const,
          searchable: true,
           required: true,
          options: [
            { value: "pending", label: "Pending" },
            { value: "active", label: "Active" },
            { value: "completed", label: "Completed" },
            { value: "approved", label: "Approved" },
            { value: "inactive", label: "Inactive" },
          ],
          description: "Current project status",
          defaultValue: "pending",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "priority",
          label: "Priority",
          type: "select" as const,
          searchable: true,
           required: true,
          options: [
            { value: "low", label: "Low" },
            { value: "medium", label: "Medium" },
            { value: "high", label: "High" },
            { value: "urgent", label: "Urgent" },
          ],
          defaultValue: "medium",
          description: "Project priority level",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
         {
          name: "clientId",
          label: "Client",
          type: "select" as const,
          searchable: true,
          options: clients?.filter(client => client._id).map(client => ({
            value: client._id as string,
            label: `${client.name}${client.company ? ` (${client.company})` : ''}`
          })) || [],
          placeholder: "Select a client",
          required: true,
          description: "The client for this project",
          cols: 12,
          mdCols: 4,
          lgCols: 4,
        },
        // {
        //   name: "projectType",
        //   label: "Project Type",
        //   type: "text" as const,
        //   placeholder: "e.g., Web Development, Mobile App, etc.",
        //   description: "The type or category of project",
        //   cols: 12,
        //   mdCols: 6,
        //   lgCols: 6,
        // },
         {
          name: "projectType",
          label: "Project Type",
          type: "select" as const,
          searchable: true,
          options: [
            { value: "web", label: "Web Development" },
            { value: "mobile", label: "Mobile App" },
            { value: "desktop", label: "Desktop Software" },
            { value: "api", label: "API Development" },
            { value: "consulting", label: "Consulting" },
            { value: "other", label: "Other" },
          ],
          description: "Type of project",
          cols: 12,
          mdCols: 4,
          lgCols: 4,
        },
        {
          name: "complexity",
          label: "Complexity",
          type: "select" as const,
          searchable: true,
          options: [
            { value: "simple", label: "Simple" },
            { value: "medium", label: "Medium" },
            { value: "complex", label: "Complex" },
          ],
          description: "Project complexity level",
          cols: 12,
          mdCols: 4,
          lgCols: 4,
        },
        {
          name: "requirements",
          label: "Key Requirements",
          type: "array-input" as const,
          placeholder: "List project requirements and specifications",
          description: "Detailed project requirements",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "customerServices",
          label: "Customer Services",
          type: "array-input" as const,
          placeholder: "List customer services provided",
          description: "Detailed customer services provided",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "description",
          label: "Description",
          type: "rich-text" as const,
          placeholder: "Describe the project objectives and scope",
          description: "Detailed project description",
          cols: 12,
          mdCols: 12,
          lgCols: 12,
        },

      ]
    },
    {
      subform_title: "Dates & Budget Breakdown",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "budget",
          label: "Total Budget",
          type: "number" as const,
          placeholder: "Enter total budget",
          description: "Total project budget",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "startDate",
          label: "Start Date",
          type: "date" as const,
          description: "Project start date",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "endDate",
          label: "End Date",
          type: "date" as const,
          description: "Project end date",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.development",
          label: "Development Costs",
          type: "number" as const,
          placeholder: "Development costs",
          description: "Estimated development costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.design",
          label: "Design Costs",
          type: "number" as const,
          placeholder: "Design costs",
          description: "Estimated design costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.testing",
          label: "Testing Costs",
          type: "number" as const,
          placeholder: "Testing costs",
          description: "Estimated testing costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.deployment",
          label: "Deployment Costs",
          type: "number" as const,
          placeholder: "Deployment costs",
          description: "Estimated deployment costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.maintenance",
          label: "Maintenance Costs",
          type: "number" as const,
          placeholder: "Maintenance costs",
          description: "Estimated maintenance costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.contingency",
          label: "Contingency",
          type: "number" as const,
          placeholder: "Contingency budget",
          description: "Contingency budget for unexpected costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
      ]
    },
    {
      subform_title: "Resources",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "timeline",
          label: "Timeline",
          type: "text" as const,
          placeholder: "Expected project duration (e.g., 3-6 months)",
          description: "Expected timeline or duration",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
         {
          name: "resources.actualHours",
          label: "Actual Hours",
          type: "number" as const,
          placeholder: "Actual hours spent",
          description: "Actual hours spent so far",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {

          name: "resources.estimatedHours",
          label: "Estimated Hours",
          type: "number" as const,
          placeholder: "Total estimated hours",
          description: "Total estimated hours for the project",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
       
        {
          name: "resources.tools",
          label: "Tools & Technologies",
          type: "array-input" as const,
          placeholder: "Add tool or technology",
          description: "Tools and technologies used in the project",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "resources.externalResources",
          label: "External Resources",
          type: "array-input" as const,
          placeholder: "Add external resource",
          description: "External resources and dependencies",
          cols: 12,
          mdCols: 6,
        },
      ]
    },
    {
      subform_title: "Risks",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "risks",
          label: "Risks",
          type: "array-object" as const,
          description: "Project risks",
          cols: 12,
          fields: [
            {
              name: "description",
              label: "Description",
              type: "text" as const,
              required: true,
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
            {
              name: "impact",
              label: "Impact",
              type: "select" as const,
              defaultValue: "medium",
              options: [
                { value: "low", label: "Low" },
                { value: "medium", label: "Medium" },
                { value: "high", label: "High" },
                { value: "critical", label: "Critical" },
              ],
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
            {
              name: "probability",
              label: "Probability",
              type: "select" as const,
              defaultValue: "medium",
              options: [
                { value: "low", label: "Low" },
                { value: "medium", label: "Medium" },
                { value: "high", label: "High" },
              ],
              cols: 12,
              mdCols: 6,
              lgCols: 4,
            },
            {
              name: "mitigation",
              label: "Mitigation",
              type: "text" as const,
              cols: 12,
              mdCols: 6,
              lgCols: 4,
            },
            {
              name: "status",
              label: "Status",
              type: "select" as const,
              defaultValue: "identified",
              options: [
                { value: "identified", label: "Identified" },
                { value: "mitigated", label: "Mitigated" },
                { value: "occurred", label: "Occurred" },
              ],
              cols: 12,
              mdCols: 6,
              lgCols: 4,
            },
          ]
        },
      ]
    },
  ];



  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Save className="h-5 w-5" />
                Edit Project
              </CardTitle>
              <p className="text-sm text-muted-foreground mt-1">
                Update project information
              </p>
            </div>
            <Badge variant="outline">
              {project?.status || 'pending'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">

            <GenericForm
              form={form}
              onSubmit={handleSubmit}
              fields={formFields}
              loading={loading || actionLoading}
              submitText={loading || actionLoading ? "Updating..." : "Update Project"}
              showCancel={false}
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}