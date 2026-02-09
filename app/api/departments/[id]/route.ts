import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Department from "@/models/Department"
import User from "@/models/User"          
import { updateDepartmentSchema, departmentIdSchema } from "@/lib/validations/department"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { performSoftDelete, addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import { createErrorResponse } from "@/lib/security/error-handler"


interface RouteParams {
  params: Promise<{ id: string }>
}

// Helper to create consistent error responses
// function createErrorResponse(message: string, status: number, details?: any) {
//   return NextResponse.json({
//     success: false,
//     error: message,
//     ...(details && { details })
//   }, { status })
// }

// GET /api/departments/[id] - Get department by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'departments', 'read')
    const { id } = await params

    // Validate department ID
    const validatedParams = departmentIdSchema.parse({ id })

    // Find department with automatic connection management
    const department = await executeGenericDbQuery(async () => {
      // Apply soft delete filter - only super admins can see deleted departments
      const filter = addSoftDeleteFilter({ _id: validatedParams.id }, isSuperAdmin, false)

      const dept = await Department.findOne(filter).lean()

      if (!dept) {
        throw new Error("Department not found")
      }
      return dept
    }, `department-${validatedParams.id}-${isSuperAdmin ? 'admin' : 'user'}`, 300000) // 5-minute cache

    return NextResponse.json({
      success: true,
      data: department,
      message: 'Department retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching department:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid department ID'
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch department'
    }, { status: 500 })
  }
}

// PUT /api/departments/[id] - Update department
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'departments', 'update')
    console.log('Middleware passed for updating department')

    // Validate department ID
    const { id } = await params
    const validatedParams = departmentIdSchema.parse({ id })

    const body = await request.json()
    const validatedData = updateDepartmentSchema.parse(body)

    // Prevent setting status to 'deleted' through update (use DELETE endpoint)
    if (validatedData.status === 'deleted') {
      return createErrorResponse('Cannot set status to deleted through update. Use DELETE endpoint instead.', 400)
    }

    // Update department with automatic connection management
    const updatedDepartment = await executeGenericDbQuery(async () => {
      // Check if department exists (apply soft delete filter - prevent updates on deleted records unless super admin)
      const filter = addSoftDeleteFilter({ _id: validatedParams.id }, isSuperAdmin, false)
      const existingDepartment = await Department.findOne(filter)
      // console.log('Existing Department:', existingDepartment)

      if (!existingDepartment) {
        throw new Error("Department not found or has been deleted")
      }

      // Check if department is deleted
      if (!isSuperAdmin && (existingDepartment.status === 'deleted' || existingDepartment.isDeleted === true)) {
        throw new Error('Cannot update Deleted entity')
      }

      // Check if new name already exists (if name is being updated, exclude deleted departments)
      if (validatedData.name && validatedData.name !== existingDepartment.name) {
        const duplicateDepartment = await Department.findOne({
          name: { $regex: new RegExp(`^${validatedData.name}$`, 'i') },
          _id: { $ne: validatedParams.id },
          status: { $ne: 'deleted' }
        })

        if (duplicateDepartment) {
          throw new Error("Department name already exists")
        }
      }

      // Update department
      return await Department.findByIdAndUpdate(
        validatedParams.id,
        { ...validatedData, updatedAt: new Date() },
        { new: true, runValidators: true }
      ).lean()
    })

    // Clear department-related caches
    clearCache(`department-${validatedParams.id}`)
    clearCache('departments')

    return NextResponse.json({
      success: true,
      data: updatedDepartment,
      message: 'Department updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating department:', error)
    console.log('Error details:', error.message);

    if (error.message === 'Cannot update Deleted entity') {
      console.log('Handling Cannot update Deleted entity error');
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 400 })
    }

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      }, { status: 400 })
    }

    if (error.code === 11000) {
      return NextResponse.json({
        success: false,
        error: 'Department name already exists'
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update department'
    }, { status: 500 })
  }
}

// DELETE /api/departments/[id] - Soft delete department
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'departments', 'delete')

    // Validate department ID
    const { id } = await params
    const validatedParams = departmentIdSchema.parse({ id })

    // Get current user for soft delete
    // const currentUser = await executeGenericDbQuery(async () => {
    //   return await User.findOne({ email: userEmail }).select('_id').lean()
    // }, `current-user-${userEmail}`, 60000)

    // if (!currentUser) {
    //   return createErrorResponse('User not found', 403)
    // }

    // Check if department exists (exclude already deleted departments)
    const existingDepartment = await executeGenericDbQuery(async () => {
      const filter = addSoftDeleteFilter({ _id: validatedParams.id }, false) // Don't include deleted for validation
      return await Department.findOne(filter)
    })

    if (!existingDepartment) {
      return createErrorResponse('Department not found or already deleted', 404)
    }

    // Perform soft delete using the generic utility
    const deleteResult = await performSoftDelete('department', validatedParams.id, userEmail)

    if (!deleteResult.success) {
      return createErrorResponse(deleteResult.message, 400)
    }

    return NextResponse.json({
      success: true,
      message: deleteResult.message,
      data: deleteResult.data
    })

  } catch (error: any) {
    console.error('Error deleting department:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid department ID'
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete department'
    }, { status: 500 })
  }
}