import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Role, { type IRole } from "@/models/Role"
import User from "@/models/User"
import { z } from "zod"
import mongoose, { type Document } from "mongoose"
import { updateRoleSchema } from "@/lib/validations/role"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { performSoftDelete, addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import { createErrorResponse } from "@/lib/security/error-handler"


// Simple cache for individual role lookups
const roleCache = new Map<string, { data: any, timestamp: number }>()
const CACHE_TTL = 2 * 60 * 1000 // 2 minutes

// Helper functions
function getClientInfo(request: NextRequest) {
  return {
    ip: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
    userAgent: request.headers.get('user-agent') || 'unknown'
  }
}

// function createErrorResponse(message: string, status: number, details?: any) {
//   return NextResponse.json({
//     success: false,
//     error: message,
//     ...(details && { details })
//   }, { status })
// }

// Permission schema for validation
const permissionSchema = z.object({
  resource: z.string().min(2).max(50).regex(/^[a-z][a-z0-9_]*$/),
  actions: z.array(z.enum(['create', 'read', 'update', 'delete', 'assign', 'approve', 'reject', 'export', 'import', 'archive', 'manage', 'configure', 'audit'])).min(1),
  conditions: z.object({
    own: z.boolean().optional(),
    department: z.boolean().optional(),
    assigned: z.boolean().optional(),
    subordinates: z.boolean().optional(),
    unrestricted: z.boolean().optional(),
  }).optional()
})




// GET /api/roles/[id] - Get single role by ID
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'roles', 'read')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid role ID', 400)
    }

    // Check user-specific cache first
    const userCacheKey = `${id}_${user._id || user.id}_${user.role?.name || 'no_role'}_${isSuperAdmin ? 'admin' : 'user'}`
    const cached = roleCache.get(userCacheKey)
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return NextResponse.json({
        success: true,
        data: cached.data
      })
    }

    const roleData = await executeGenericDbQuery(async () => {
      // Apply soft delete filter - only super admins can see deleted roles
      const filter = addSoftDeleteFilter({ _id: id }, isSuperAdmin)

      const role = await Role.findOne(filter)
        .populate('departmentDetails', 'name description status')
        .populate('userCount')
        .select('-__v') // Exclude version field but include all other fields including permissions
        .lean()
        .exec() as (IRole & Document) | null

      if (!role) {
        throw new Error('Role not found')
      }

      // Get additional role statistics (exclude deleted users)
      const [usersWithRole, activeUsersWithRole] = await Promise.all([
        User.countDocuments({ role: role._id, status: { $ne: 'deleted' } }),
        User.countDocuments({ role: role._id, status: 'active' })
      ])

      return {
        ...role,
        statistics: {
          totalUsers: usersWithRole,
          activeUsers: activeUsersWithRole,
          inactiveUsers: usersWithRole - activeUsersWithRole,
          utilizationRate: role.maxUsers ? Math.round((usersWithRole / role.maxUsers) * 100) : null
        }
      }
    }, `role-${id}-${user._id || user.id}-${isSuperAdmin ? 'admin' : 'user'}`, CACHE_TTL)

    // Log access
    console.log('Role accessed:', {
      userId: userEmail,
      roleId: id,
      roleName: roleData.name,
      ip: getClientInfo(request).ip
    })

    return NextResponse.json({
      success: true,
      data: roleData,
      message: 'Role retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/roles/[id]:', error)
    return createErrorResponse("Internal server error", 500)
  }
}

// PUT /api/roles/[id] - Update role
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'roles', 'update')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid role ID', 400)
    }

    const body = await request.json()

    // Validate update data
    const validation = updateRoleSchema.safeParse(body)
    if (!validation.success) {
      return createErrorResponse("Validation failed", 400, validation.error.errors)
    }

    const updateData = validation.data

    // Prevent setting status to 'deleted' through update (use DELETE endpoint)
    if (updateData.status === 'deleted') {
      return createErrorResponse('Cannot set status to deleted through update. Use DELETE endpoint instead.', 400)
    }

    // Check if role exists (apply soft delete filter - prevent updates on deleted records unless super admin)
    const existingRole = await executeGenericDbQuery(async () => {
      const filter = addSoftDeleteFilter({ _id: id }, isSuperAdmin)
      return await Role.findOne(filter)
    }) as IRole | null
    if (!existingRole) {
      return createErrorResponse('Role not found or has been deleted', 404)
    }

    // Check if role is deleted
    if (!isSuperAdmin && (existingRole.status === 'deleted' || existingRole.isDeleted === true)) {
      throw new Error('Cannot update Deleted entity')
    }

    // isSuperAdmin already available from middleware

    // CRITICAL: Protect superadmin role from being modified
    // Check if this role is assigned to super_admin
    const superAdminUser = await User.findOne({
      role: id
    }).populate('role').lean()

    if (superAdminUser && (superAdminUser.role as any)?.name === 'super_admin') {
      return createErrorResponse('Super Administrator role cannot be modified. This role is protected to maintain system security.', 403)
    }

    // Prevent updating system roles
    // if (existingRole.isSystemRole) {
    //   return createErrorResponse('System roles cannot be modified', 403)
    // }

    // Extra protection for super admin roles by name
    if (existingRole.name === 'super_admin' || existingRole.name === 'superadmin' || (existingRole.metadata as any)?.isImmutable) {
      return createErrorResponse('Super Administrator role is protected and cannot be modified', 403)
    }

    // Check user permissions - only super admins can modify high-level roles
    if (!isSuperAdmin && existingRole.hierarchyLevel >= 8) {
      return createErrorResponse('Only Super Administrators can modify high-level roles', 403)
    }

    // Check for name conflicts if name is being updated (exclude deleted roles)
    if (updateData.name && updateData.name !== existingRole.name) {
      const nameConflict = await Role.findOne({
        name: updateData.name,
        department: existingRole.department,
        _id: { $ne: id },
        status: { $ne: 'deleted' }
      })

      if (nameConflict) {
        return createErrorResponse('Role with this name already exists in the department', 409)
      }
    }

    // Check user limit constraints if maxUsers is being reduced (exclude deleted users)
    if (updateData.maxUsers && updateData.maxUsers < (existingRole.maxUsers || Infinity)) {
      const currentUserCount = await User.countDocuments({ role: id, status: { $ne: 'deleted' } })
      if (currentUserCount > updateData.maxUsers) {
        return createErrorResponse(
          `Cannot reduce user limit below current user count (${currentUserCount})`,
          400
        )
      }
    }

    // Update role
    const updatedRole = await executeGenericDbQuery(async () => {
      return await Role.findByIdAndUpdate(
        id,
        {
          ...updateData,
          'metadata.updatedBy': userEmail || 'unknown',
          'metadata.updatedAt': new Date(),
        },
        {
          new: true,
          runValidators: true
        }
      )
        .populate('departmentDetails', 'name description status')
        .lean()
    }, `role-update-${id}`) as (IRole & Document) | null

    // Log successful update
    console.log('Role updated successfully:', {
      updatedBy: userEmail,
      roleId: id,
      roleName: updatedRole?.name,
      changes: Object.keys(updateData),
      ip: getClientInfo(request).ip
    })

    return NextResponse.json({
      success: true,
      data: updatedRole,
      message: 'Role updated successfully'
    })

  } catch (error: any) {
    console.error('Error in PUT /api/roles/[id]:', error)

    if (error.message === 'Cannot update Deleted entity') {
      return createErrorResponse(error.message, 400)
    }

    // Handle specific MongoDB errors
    if (error.code === 11000) {
      return createErrorResponse("Role name already exists in this department", 409)
    }

    return createErrorResponse("Failed to update role", 500)
  }
}

// DELETE /api/roles/[id] - Soft delete role
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'roles', 'delete')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid role ID', 400)
    }

    // Check if role exists (exclude already deleted roles)
    const existingRole = await executeGenericDbQuery(async () => {
      const filter = addSoftDeleteFilter({ _id: id }, false) // Don't include deleted for validation
      return await Role.findOne(filter)
    }) as (IRole & Document) | null
    if (!existingRole) {
      return createErrorResponse('Role not found or already deleted', 404)
    }

    // Prevent deleting system roles
    if (existingRole.isSystemRole) {
      return createErrorResponse('System roles cannot be deleted', 403)
    }

    // Extra protection for super admin roles
    if (existingRole.name === 'super_admin') {
      return createErrorResponse('Super Administrator role is protected and cannot be deleted', 403)
    }

    // Prevent non-super admins from deleting high-level roles
    if (!isSuperAdmin && existingRole.hierarchyLevel >= 8) {
      return createErrorResponse('Only Super Administrators can delete high-level roles', 403)
    }

    // Perform soft delete using the generic utility
    const deleteResult = await performSoftDelete('role', id, userEmail)

    if (!deleteResult.success) {
      return createErrorResponse(deleteResult.message, 400)
    }

    return NextResponse.json({
      success: true,
      message: deleteResult.message,
      data: deleteResult.data
    })

  } catch (error: any) {
    console.error('Error in DELETE /api/roles/[id]:', error)
    return createErrorResponse("Failed to delete role", 500)
  }
}