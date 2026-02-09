"use client";

import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useLeads } from "@/hooks/use-leads";
import { CreateLeadFormData, createLeadFormSchema } from "@/lib/validations/lead";
import { useNavigation } from "@/components/providers/navigation-provider";
export default function AddLeadPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { createLead, actionLoading } = useLeads();
  const { navigateTo, isNavigating } = useNavigation()
  const form = useForm<CreateLeadFormData>({
    resolver: zodResolver(createLeadFormSchema),
    defaultValues: {
      // Client Information
      name: "",
      email: "",
      phone: "",
      position: "",
      company: "",
      website: undefined,
      industry: "",
      companySize: undefined,
      annualRevenue: "",
      employeeCount: "",
      status: "active",
      source: "website",
      priority: "medium",
      nextFollowUpDate: "",
      notes: "",
        // Address Information
      address: {
        street: "",
        city: "",
        state: "",
        zipCode: "",
        country: "",
      },
      socialLinks: [],
      // Project Information
      projectName: "",
      projectType: undefined,
      complexity: undefined,
      projectBudget: "",
      estimatedHours: "",
      projectTimeline: "",
      projectDescription: "",
      technologies: [],
      projectRequirements: [],
      customerServices: [],

      // Arrays
      tags: [],
    },
  });

  const handleSubmit = async (data: CreateLeadFormData) => {
    try {
      // Transform form data to API format
      const cleanedData = {
        ...data,
        // Client Information
        phone: data.phone?.trim() || undefined,
        position: data.position?.trim() || undefined,
        company: data.company?.trim() || undefined,
        website: data.website?.trim() || undefined,
        industry: data.industry?.trim() || undefined,
        companySize: data.companySize || undefined,
        annualRevenue: data.annualRevenue ? Number(data.annualRevenue) : undefined,
        employeeCount: data.employeeCount ? Number(data.employeeCount) : undefined,
        notes: data.notes?.trim() || undefined,
        nextFollowUpDate: data.nextFollowUpDate ? new Date(data.nextFollowUpDate) : undefined,
        status: data.status || "active", // Ensure status is always set
         // Address
        address: data.address ? {
          street: data.address.street?.trim() || undefined,
          city: data.address.city?.trim() || undefined,
          state: data.address.state?.trim() || undefined,
          zipCode: data.address.zipCode?.trim() || undefined,
          country: data.address.country?.trim() || undefined,
        } : undefined,
        // Project Information
        projectName: data.projectName?.trim() || '',
        projectType: data.projectType || undefined,
        complexity: data.complexity || undefined,
        projectBudget: data.projectBudget ? Number(data.projectBudget) : undefined,
        estimatedHours: data.estimatedHours ? Number(data.estimatedHours) : undefined,
        projectTimeline: data.projectTimeline?.trim() || undefined,
        projectDescription: data.projectDescription?.trim() || undefined,
        technologies: data.technologies?.filter((tech: string) => tech.trim().length > 0) || [],
        projectRequirements: data.projectRequirements?.filter((req: string) => req.trim().length > 0) || [],
        customerServices: data.customerServices?.filter((service: string) => service.trim().length > 0) || [],

        // Arrays and other fields
        tags: data.tags?.filter((tag: string) => tag.trim().length > 0) || [],
        // Default values for required fields
        hotLead: false,
      };

      await createLead(cleanedData);

      toast({
        title: "Success",
        description: "Lead created successfully",
      });

      navigateTo("/leads");
    } catch (error: any) {
      console.error('Create lead error:', error)

      // Handle structured API errors
      let errorMessage = "Failed to create lead"
      let errorDetails = ""

      if (error?.error) {
        errorMessage = error.error
        if (error.details && Array.isArray(error.details)) {
          errorDetails = error.details.join(', ')
        } else if (error.details) {
          errorDetails = typeof error.details === 'string' ? error.details : JSON.stringify(error.details)
        }
      } else if (error?.message) {
        errorMessage = error.message
      }

      toast({
        title: "Error",
        description: errorDetails ? `${errorMessage}: ${errorDetails}` : errorMessage,
        variant: "destructive",
      });
    }
  };

  const handleCancel = () => {
    navigateTo("/leads");
  };

  const formFields = [
    {
      subform_title: "Client Information",
      fields: [
        {
          name: "name",
          label: "Contact Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter contact name",
          description: "Full name of the primary contact",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "email",
          label: "Email Address",
          type: "email" as const,
          required: true,
          placeholder: "contact@company.com",
          description: "Primary email address for communication",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "phone",
          label: "Phone Number",
          type: "text" as const,
          placeholder: "+1 (555) 123-4567",
          description: "Phone number with country code",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "status",
          label: "Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "active", label: "Active" },
            { value: "inactive", label: "Inactive" },
          ],
          cols: 12,
          mdCols: 6,
        },
      ]
    },
    {
      subform_title: "Company Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "company",
          label: "Company Name",
          type: "text" as const,
          placeholder: "Enter company name",
          description: "Company or organization name",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "website",
          label: "Company Website",
          type: "text" as const,
          placeholder: "https://www.company.com",
          description: "Company website URL",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "position",
          label: "Job Title",
          type: "text" as const,
          placeholder: "CEO, CTO, Manager, etc.",
          description: "Contact's job title or position",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "industry",
          label: "Industry",
          type: "text" as const,
          placeholder: "Technology, Healthcare, Finance, etc.",
          description: "Industry or sector the company operates in",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "companySize",
          label: "Company Size",
          type: "select" as const,
          searchable: true,
          options: [
            { value: "startup", label: "Startup (1-10 employees)" },
            { value: "small", label: "Small (11-50 employees)" },
            { value: "medium", label: "Medium (51-200 employees)" },
            { value: "large", label: "Large (201-1000 employees)" },
            { value: "enterprise", label: "Enterprise (1000+ employees)" },
          ],
          description: "Approximate company size",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "annualRevenue",
          label: "Annual Revenue",
          type: "text" as const,
          placeholder: "5000000",
          description: "Annual revenue in USD (optional)",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "employeeCount",
          label: "Employee Count",
          type: "text" as const,
          placeholder: "50",
          description: "Number of employees in the company",
          cols: 12,
          mdCols: 4,
        },
      ]
    },
    {
      subform_title: "Address Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "address.street",
          label: "Street Address",
          type: "text" as const,
          placeholder: "123 Main Street",
          description: "Street address",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "address.city",
          label: "City",
          type: "text" as const,
          placeholder: "New York",
          description: "City",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "address.state",
          label: "State/Province",
          type: "text" as const,
          placeholder: "NY",
          description: "State or province",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "address.zipCode",
          label: "ZIP/Postal Code",
          type: "text" as const,
          placeholder: "10001",
          description: "ZIP or postal code",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "address.country",
          label: "Country",
          type: "text" as const,
          placeholder: "United States",
          description: "Country",
          cols: 12,
          mdCols: 4,
        },
      ]
    },
    {
      subform_title: "Social Links",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "socialLinks",
          label: "Social Links",
          type: "array-object" as const,
          description: "Lead's Social links",
          cols: 12,
          fields: [
            {
              name: "linkName",
              label: "Social Media Platform",
              type: "text" as const,
              required: true,
              description: "Social media platform name",
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
            {
              name: "linkUrl",
              label: "Social Media Url",
              type: "url" as const,
              required: true,
              description: "Social media platform URL",
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
          ]
        },
      ]
    },
    {
      subform_title: "Source & Follow-up",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "source",
          label: "Lead Source",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "website", label: "Website" },
            { value: "referral", label: "Referral" },
            { value: "cold_call", label: "Cold Call" },
            { value: "email", label: "Email Marketing" },
            { value: "social_media", label: "Social Media" },
            { value: "event", label: "Event/Conference" },
            { value: "partner", label: "Partner" },
            { value: "advertising", label: "Advertising" },
            { value: "other", label: "Other" },
          ],
          cols: 12,
          mdCols: 4,
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
          cols: 12,
          mdCols: 4,
        },
        {
          name: "nextFollowUpDate",
          label: "Next Follow-up",
          type: "date" as const,
          description: "Schedule next follow-up date",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "notes",
          label: "Notes",
          type: "rich-text" as const,
          placeholder: "Add any additional notes about this lead...",
          description: "Internal notes about the lead",
          cols: 12,
          rows: 3,
        },
      ]
    },
    {
      subform_title: "Project Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "projectName",
          label: "Project Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter project name",
          description: "Name or title of the proposed project",
          cols: 12,
          mdCols: 6,
        },
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
          mdCols: 3,
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
          mdCols: 3,
        },
        {
          name: "projectBudget",
          label: "Budget (USD)",
          type: "text" as const,
          placeholder: "50000",
          description: "Estimated project budget in USD",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "estimatedHours",
          label: "Estimated Hours",
          type: "text" as const,
          placeholder: "160",
          description: "Estimated total hours for the project",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "projectTimeline",
          label: "Timeline",
          type: "text" as const,
          placeholder: "3-6 months",
          description: "Expected project duration or timeline",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "projectDescription",
          label: "Project Description",
          type: "rich-text" as const,
          placeholder: "Describe the project requirements and goals...",
          description: "Detailed description of the project",
          cols: 12,
          rows: 4,
        },
        {
          name: "customerServices",
          label: "Customer Services",
          type: "array-input" as const,
          placeholder: "Add Services that Customers Offers in his Business...",
          description: "Required customer services for the project",
          cols: 12,
        },
        {
          name: "technologies",
          label: "Tools & Technologies",
          type: "array-input" as const,
          placeholder: "Add technology...",
          description: "Required technologies for the project",
          cols: 6,
        },
        {
          name: "projectRequirements",
          label: "Key Requirements",
          type: "array-input" as const,
          placeholder: "Add requirement...",
          description: "Key requirements and features needed",
          cols: 6,
        },
      ]
    }
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Add New Lead"
        subtitle="Create a new sales lead with client and project information"
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={actionLoading}
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Leads
          </Button>
        }
      />

      <div>
        <GenericForm
          form={form}
          fields={formFields}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
          loading={actionLoading}
          submitText="Create Lead"
          cancelText="Cancel"
        />
      </div>
    </div>
  );
}