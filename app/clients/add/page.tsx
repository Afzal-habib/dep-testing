"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useClients } from "@/hooks/use-clients";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { CreateClientFormData, createClientFormSchema, CreateClientData } from '@/lib/validations/client';
import { useNavigation } from "@/components/providers/navigation-provider";

export default function AddClientPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { createClient, actionLoading } = useClients();
  const { navigateTo } = useNavigation()

  const form = useForm({
    resolver: zodResolver(createClientFormSchema),
    defaultValues: {
      // Basic Information
      name: "",
      email: "",
      phone: "",
      position: "",

      // Company Information
      company: "",
      website: "",
      industry: "",
      companySize: undefined,
      annualRevenue: "",
      employeeCount: "",

      // Client Status
      clientStatus: "qualified",
      status: "qualified",


      // Address Information
      address: {
        street: "",
        city: "",
        state: "",
        zipCode: "",
        country: "",
      },

      // Social Links
      socialLinks: [],


      // Notes
      notes: "",
    },
  });

  const handleSubmit = async (data: CreateClientFormData) => {
    try {
      // Transform form data to API format
      const cleanedData = {
        // Required fields from form
        name: data.name,
        email: data.email,
        phone: data.phone?.trim() || undefined,
        position: data.position?.trim() || undefined,
        company: data.company?.trim() || '',
        website: data.website?.trim() || '',

        // Status fields
        status: data.status || 'qualified',
        clientStatus: data.clientStatus,


        // Address
        address: data.address ? {
          street: data.address.street?.trim() || undefined,
          city: data.address.city?.trim() || undefined,
          state: data.address.state?.trim() || undefined,
          zipCode: data.address.zipCode?.trim() || undefined,
          country: data.address.country?.trim() || undefined,
        } : undefined,

        // Social links
        socialLinks: data.socialLinks ? data.socialLinks.map(item => ({
          linkName: item.linkName,
          linkUrl: item.linkUrl as string,
        })) : undefined,


        // Required API fields with defaults
        emailVerified: false,
        phoneVerified: false,
        twoFactorEnabled: false,
        permissions: [],
      };

      await createClient(cleanedData);

      toast({
        title: "Success",
        description: "Client created successfully",
      });

      navigateTo("/clients");
    } catch (error: any) {
      console.error('Create client error:', error)

      // Handle structured API errors
      let errorMessage = "Failed to create client"
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

  const { isNavigating, handleNavigation } = useNavigationLoading();

  const handleCancel = () => {
    handleNavigation("/clients");
  };

  const formFields = [
    {
      subform_title: "Basic Information",
      fields: [
        {
          name: "name",
          label: "Client Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter client name",
          description: "Full name of the client",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "email",
          label: "Email Address",
          type: "email" as const,
          required: true,
          placeholder: "client@company.com",
          description: "Primary email address for communication",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "phone",
          label: "Phone Number",
          type: "text" as const,
          placeholder: "+1 (555) 123-4567",
          description: "Phone number with country code",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "position",
          label: "Job Title",
          type: "text" as const,
          placeholder: "CEO, CTO, Manager, etc.",
          description: "Client's job title or position",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "clientStatus",
          label: "Client Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "qualified", label: "Qualified" },
            { value: "unqualified", label: "Unqualified" },
          ],
          description: "Client qualification status",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "status",
          label: "Account Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "active", label: "Active" },
            { value: "inactive", label: "Inactive" },
            { value: "qualified", label: "Qualified" },
            { value: "unqualified", label: "Unqualified" },
          ],
          description: "Account status",
          cols: 12,
          mdCols: 4,
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
          required: true,
          placeholder: "Enter company name",
          description: "Company or organization name",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "website",
          label: "Company Website",
          type: "url" as const,
          required: true,
          placeholder: "Enter company website url",
          description: "Company or organization website",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "industry",
          label: "Industry",
          type: "text" as const,
          placeholder: "Technology, Healthcare, Finance, etc.",
          description: "Industry or sector the company operates in",
          cols: 12,
          mdCols: 4,
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
          description: "Client's Social links",
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
      subform_title: "Additional Notes",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "notes",
          label: "Notes",
          type: "rich-text" as const,
          placeholder: "Add any additional notes about this client...",
          description: "Internal notes about the client",
          cols: 12,
          rows: 3,
        },
      ]
    }
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Add New Client"
        subtitle="Create a new client record"
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isNavigating}
          >
            <ArrowLeft className={`h-4 w-4 mr-2 ${isNavigating ? 'animate-spin' : ''}`} />
            {isNavigating ? 'Going back...' : 'Back to Clients'}
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
          submitText="Create Client"
          cancelText="Cancel"
        />
      </div>
    </div>
  );
}