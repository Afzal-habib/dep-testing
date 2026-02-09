import mongoose from 'mongoose'
import { clearCache } from '../mongodb'

// Type definitions for dependency checking
interface DependencyCheck {
    model: string
    field: string
    errorMessage: string
}

// Dependency map for soft delete checks
const DEPENDENCY_CHECKS: Record<string, DependencyCheck[]> = {
    department: [
        {
            model: 'User',
            field: 'department',
            errorMessage: 'Cannot delete department: active users are assigned to this department'
        },
        {
            model: 'Role',
            field: 'department',
            errorMessage: 'Cannot delete department: active roles are assigned to this department'
        }
    ],
    role: [
        {
            model: 'User',
            field: 'role',
            errorMessage: 'Cannot delete role: active users are assigned to this role'
        }
    ],
    user: [], // Regular users have no dependencies by default
    client: [
        {
            model: 'Project',
            field: 'clientId',
            errorMessage: 'Cannot delete client: active projects are assigned to this client'
        }
    ], // Clients can be deleted (they are created from leads, so no dependencies)
    lead: [
        {
            model: 'User',
            field: 'leadId',
            errorMessage: 'Cannot delete lead: an active client is created from this lead. Delete the client first.'
        }
    ], // Leads cannot be deleted if a client exists for them
    project: [
        {
            model: 'Task',
            field: 'projectId',
            errorMessage: 'Cannot delete project: active tasks are assigned to this project'
        }
    ],
    task: [
        {
            model: 'Task',
            field: 'parentTaskId',
            errorMessage: 'Cannot delete task: active sub-tasks are assigned to this task'
        },
        {
            model: 'TimeLog',
            field: 'taskId',
            errorMessage: 'Cannot delete task: time logs are recorded for this task'
        }
    ]
}/**
 * Generic function to check if an entity can be soft deleted
 * @param modelName - The name of the model (lowercase)
 * @param entityId - The ID of the entity to check
 * @returns Promise<{ canDelete: boolean, reason?: string }>
 */
export async function canSoftDelete(
    modelName: string,
    entityId: string
): Promise<{ canDelete: boolean; reason?: string }> {
    try {
        // Validate ObjectId
        if (!mongoose.Types.ObjectId.isValid(entityId)) {
            return { canDelete: false, reason: 'Invalid entity ID' }
        }

        // Get dependency checks for this model
        let checks = DEPENDENCY_CHECKS[modelName.toLowerCase()] || []

        // Special handling for users - check if they are clients
        if (modelName.toLowerCase() === 'user') {
            const UserModel = mongoose.models.User
            if (UserModel) {
                const user = await UserModel.findById(entityId).select('isClient')
                if (user?.isClient) {
                    // If this is a client user, use client dependency checks (which is empty - clients can be deleted)
                    checks = DEPENDENCY_CHECKS['client'] || []
                }
            }
        }

        // If no dependency checks, entity can be deleted
        if (checks.length === 0) {
            return { canDelete: true }
        }

        // Check each dependency
        for (const check of checks) {
            const DependentModel = mongoose.models[check.model]
            if (!DependentModel) {
                console.warn(`Model ${check.model} not found for dependency check`)
                continue
            }

            // Build dependency filter
            let dependentFilter: any = {
                [check.field]: new mongoose.Types.ObjectId(entityId),
                isDeleted: false // Exclude already soft deleted records
            }

            // Special handling for User dependencies from leads - check for active clients only
            if (check.model === 'User' && modelName.toLowerCase() === 'lead') {
                dependentFilter.isClient = true // Only check client users
                dependentFilter.isDeleted = false // Exclude deleted clients
            }

            const dependentCount = await DependentModel.countDocuments(dependentFilter)

            if (dependentCount > 0) {
                return {
                    canDelete: false,
                    reason: `${check.errorMessage} (${dependentCount} active record${dependentCount > 1 ? 's' : ''} found)`
                }
            }
        }

        return { canDelete: true }
    } catch (error) {
        console.error('Error checking soft delete dependencies:', error)
        return {
            canDelete: false,
            reason: 'Error checking dependencies. Please try again.'
        }
    }
}

/**
 * Generic function to perform soft delete on an entity
 * @param modelName - The name of the model
 * @param entityId - The ID of the entity to soft delete
 * @param userEmail - Email of the user performing the action
 * @param deletionReason - Optional reason for deletion
 * @returns Promise<{ success: boolean, message: string, data?: any }>
 */
export async function performSoftDelete(
    modelName: string,
    entityId: string,
    userEmail: string,
    deletionReason?: string
): Promise<{ success: boolean; message: string; data?: any }> {
    try {
        // Get the user ID from email
        const UserModel = mongoose.models.User
        if (!UserModel) {
            return {
                success: false,
                message: 'User model not found'
            }
        }

        const currentUser = await UserModel.findOne({ email: userEmail }).select('_id')
        if (!currentUser) {
            return {
                success: false,
                message: 'User not found'
            }
        }

        const userId = currentUser._id

        // First check if entity can be deleted
        const deleteCheck = await canSoftDelete(modelName, entityId)
        if (!deleteCheck.canDelete) {
            return {
                success: false,
                message: deleteCheck.reason || 'Cannot delete entity'
            }
        }

        // Get the model - handle Lead model specifically
        let Model
        if (modelName.toLowerCase() === 'lead') {
            Model = mongoose.models.Lead
        } else {
            Model = mongoose.models[modelName.charAt(0).toUpperCase() + modelName.slice(1)]
        }

        if (!Model) {
            return {
                success: false,
                message: `Model ${modelName} not found`
            }
        }
        console.log(`Performing soft delete for ${modelName} with ID ${entityId} by user ${userEmail}`)
        
        // Perform soft delete - existence check already done by calling endpoint
        let updatedEntity
        if (modelName.toLowerCase() === 'lead') {
            // For leads, set status to 'deleted' and soft delete fields
            updatedEntity = await Model.findByIdAndUpdate(
                entityId,
                {
                    $set: {
                        status: 'deleted',
                        isDeleted: true,
                        deletedAt: new Date(),
                        deletedBy: userId,
                        deletionReason: deletionReason,
                        updatedAt: new Date()
                    }
                },
                { new: true, runValidators: false }
            )
        } else {
            // For other models, set status to 'deleted' and soft delete fields
            updatedEntity = await Model.findByIdAndUpdate(
                entityId,
                {
                    $set: {
                        status: 'deleted',
                        isDeleted: true,
                        deletedAt: new Date(),
                        deletedBy: userId,
                        deletionReason: deletionReason,
                        updatedAt: new Date()
                    }
                },
                { new: true, runValidators: false }
            )
        }

        if (!updatedEntity) {
            return {
                success: false,
                message: `Failed to delete ${modelName}`
            }
        }

        // Clear relevant caches
        await clearCacheForEntity(modelName, entityId)

        // Log the action
        console.log(`${modelName.charAt(0).toUpperCase() + modelName.slice(1)} soft deleted:`, {
            entityId,
            entityName: updatedEntity.name || updatedEntity.projectName || updatedEntity.displayName || 'Unknown',
            deletedBy: userId,
            deletionReason: deletionReason,
            timestamp: new Date().toISOString()
        })

        return {
            success: true,
            message: `${modelName.charAt(0).toUpperCase() + modelName.slice(1)} deleted successfully`,
            data: updatedEntity
        }
    } catch (error) {
        console.error(`Error performing soft delete for ${modelName}:`, error)
        return {
            success: false,
            message: `Failed to delete ${modelName}. Please try again.`
        }
    }
}

/**
 * Clear caches related to an entity
 * @param modelName - The name of the model
 * @param entityId - The ID of the entity
 */
async function clearCacheForEntity(modelName: string, entityId: string): Promise<void> {
    try {
        const patterns = [
            `${modelName}s`, // List caches
            `${modelName}-${entityId}`, // Individual entity caches
            entityId // Any cache containing the entity ID
        ]

        for (const pattern of patterns) {
            await clearCache(pattern)
        }
    } catch (error) {
        console.error('Error clearing cache:', error)
    }
}

/**
 * Helper function to get base filter for excluding deleted records
 * @param isSuperAdmin - Whether the user is a super admin
 * @returns MongoDB filter object
 */
export function getBaseFilter(isSuperAdmin: boolean = false): Record<string, any> {
    // Always exclude deleted records from list queries
    // Super admins can access individual deleted records via direct ID queries
    return { isDeleted: false }
}

/**
 * Helper function to add soft delete filter to existing query
 * @param existingFilter - Existing MongoDB filter
 * @param isSuperAdmin - Whether the user is a super admin
 * @param isListQuery - Whether this is a list query (default true)
 * @returns Combined filter with soft delete logic
 */
export function addSoftDeleteFilter(
    existingFilter: Record<string, any>,
    isSuperAdmin: boolean = false,
    isListQuery: boolean = true
): Record<string, any> {
    // Always exclude deleted records from list queries
    // Super admins can access individual deleted records via direct ID queries
    // if (isSuperAdmin && !isListQuery) {
    if (isSuperAdmin) {
        return existingFilter
    }

    const result = { ...existingFilter }

    if (result.isDeleted !== undefined) {
        // If isDeleted already exists, combine it with soft delete filter by converting
        // the existing condition into a $and clause so both constraints are preserved.
        const existingIsDeletedFilter = typeof result.isDeleted === 'object' ? result.isDeleted : { $eq: result.isDeleted }

        // Remove the isDeleted property and combine into an $and clause for MongoDB
        delete result.isDeleted
        result.$and = result.$and || []
        result.$and.push({ isDeleted: existingIsDeletedFilter })
        result.$and.push({ isDeleted: false })
    } else {
        // If no isDeleted filter, just add the soft delete check to the filter
        result.isDeleted = false
    }

    // Return the full filter object (not only the isDeleted portion)
    return result
}

/**
 * Add a new dependency check for a model
 * @param modelName - The model name to add dependency for
 * @param checks - Array of dependency checks
 */
export function addDependencyChecks(modelName: string, checks: DependencyCheck[]): void {
    DEPENDENCY_CHECKS[modelName.toLowerCase()] = [
        ...(DEPENDENCY_CHECKS[modelName.toLowerCase()] || []),
        ...checks
    ]
}

// Export dependency checks for reference
export { DEPENDENCY_CHECKS }
