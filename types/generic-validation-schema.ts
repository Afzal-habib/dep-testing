import { z } from "zod";

// Permission validation schema
export const permissionSchema = z.object({
  resource: z.string().min(1, "Resource is required"),
  actions: z.array(z.string()).min(1, "At least one action is required"),
  conditions: z.object({
    own: z.boolean().optional(),
    department: z.boolean().optional(),
    assigned: z.boolean().optional(),
    subordinates: z.boolean().optional(),
    unrestricted: z.boolean().optional(),
  }).optional(),
});

// Role validation schema - unified for both create and edit operations
export const roleValidationSchema = z.object({
  name: z.string()
    .min(2, "Name must be at least 2 characters")
    .max(100, "Name must not exceed 100 characters")
    .regex(/^[a-zA-Z][a-zA-Z0-9\s\-_]*$/, "Name must start with letter and contain only letters, numbers, spaces, hyphens, and underscores"),
  displayName: z.string()
    .min(2, "Display name must be at least 2 characters")
    .max(150, "Display name must not exceed 150 characters"),
  description: z.string()
    .max(500, "Description must not exceed 500 characters")
    .optional(),
  department: z.string()
    .min(1, "Department is required"),
  permissions: z.array(permissionSchema)
    .min(1, "Please select at least one permission")
    .optional(), // Optional for create operations since it's handled separately
  hierarchyLevel: z.number()
    .min(1, "Hierarchy level must be at least 1")
    .max(10, "Hierarchy level must not exceed 10")
    .default(1),
  maxUsers: z.number()
    .min(1, "Max users must be at least 1")
    .max(1000, "Max users must not exceed 1000")
    .optional(),
  status: z.enum(["active", "inactive", "archived"])
    .default("active"),
  validityPeriod: z.object({
    startDate: z.string().optional(),
    endDate: z.string().optional(),
  }).optional(),
  metadata: z.object({
    notes: z.string().max(1000, "Notes must not exceed 1000 characters").optional(),
    tags: z.array(z.string()).optional(),
    createdBy: z.string().optional(),
    updatedBy: z.string().optional(),
  }).optional(),
});

// Schema for create role operations (without _id and status defaults to "active")
export const createRoleSchema = roleValidationSchema.omit({ 
  permissions: true // Remove permissions from validation as it's handled separately in the form
});

// Schema for edit role operations (includes status field and more flexible validation)
export const editRoleSchema = roleValidationSchema.extend({
  _id: z.string().optional(), // Optional for form, but should be present when updating
  status: z.enum(["active", "inactive", "archived"]).default("active"),
});

// Schema for role creation API payload (includes permissions)
export const createRoleApiSchema = roleValidationSchema.extend({
  permissions: z.array(permissionSchema).min(1, "At least one permission is required"),
});

// Schema for role update API payload
export const updateRoleApiSchema = roleValidationSchema.partial().extend({
  _id: z.string().min(1, "Role ID is required"),
  permissions: z.array(permissionSchema).min(1, "At least one permission is required").optional(),
});

// Type definitions
export type Permission = z.infer<typeof permissionSchema>;
export type RoleValidationData = z.infer<typeof roleValidationSchema>;
export type CreateRoleFormData = z.infer<typeof createRoleSchema>;
export type EditRoleFormData = z.infer<typeof editRoleSchema>;
export type CreateRoleApiData = z.infer<typeof createRoleApiSchema>;
export type UpdateRoleApiData = z.infer<typeof updateRoleApiSchema>;

// Department validation schema
export const departmentValidationSchema = z.object({
  name: z.string()
    .min(2, "Department name must be at least 2 characters")
    .max(100, "Department name must not exceed 100 characters"),
  description: z.string()
    .max(500, "Description must not exceed 500 characters")
    .optional(),
  status: z.enum(["active", "inactive"])
    .default("active"),
});

export const createDepartmentSchema = departmentValidationSchema;
export const editDepartmentSchema = departmentValidationSchema.extend({
  _id: z.string().optional(),
});



// Type definitions for departments
export type DepartmentValidationData = z.infer<typeof departmentValidationSchema>;
export type CreateDepartmentFormData = z.infer<typeof createDepartmentSchema>;
export type EditDepartmentFormData = z.infer<typeof editDepartmentSchema>;

// User validation schema (for future use)
export const userValidationSchema = z.object({
  name: z.string()
    .min(2, "Name must be at least 2 characters")
    .max(100, "Name must not exceed 100 characters"),
  email: z.string()
    .email("Please enter a valid email address"),
  phone: z.string()
    .regex(/^[\+]?[1-9][\d]{0,15}$/, "Please enter a valid phone number")
    .optional(),
  role: z.string()
    .min(1, "Role is required"),
  department: z.string()
    .min(1, "Department is required"),
  position: z.string()
    .max(100, "Position must not exceed 100 characters")
    .optional(),
  status: z.enum(["active", "inactive", "suspended"])
    .default("active"),
  address: z.object({
    street: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    country: z.string().optional(),
    zipCode: z.string().optional(),
  }).optional(),
});

export const createUserSchema = userValidationSchema.extend({
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, "Password must contain at least one lowercase letter, one uppercase letter, and one number"),
});

export const editUserSchema = userValidationSchema.extend({
  _id: z.string().optional(),
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, "Password must contain at least one lowercase letter, one uppercase letter, and one number")
    .optional(),
});

// Type definitions for users
export type UserValidationData = z.infer<typeof userValidationSchema>;
export type CreateUserFormData = z.infer<typeof createUserSchema>;
export type EditUserFormData = z.infer<typeof editUserSchema>;
