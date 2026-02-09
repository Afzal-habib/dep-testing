import { NextRequest, NextResponse } from "next/server"
import { genericApiRoutesMiddleware } from "@/lib/middleware/route-middleware"
import { executeGenericDbQuery } from "@/lib/mongodb"
import User from "@/models/User"
import { updateProfileSchema, changePasswordSchema, type UpdateProfileData, type ChangePasswordData } from "@/lib/validations/profile"
import { AuditLogger } from "@/lib/security/audit-logger"
import bcrypt from "bcryptjs"

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/profile - Get current user's profile
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: currentUser, userEmail } = await genericApiRoutesMiddleware(request, 'profile', 'read')

    const user = await executeGenericDbQuery(async () => {
      return await User.findById(session.user.id)
        .populate('role', 'name displayName hierarchyLevel permissions')
        .populate('department', 'name')
        .select('+lastLogin')
    }, `profile-${session.user.id}`, 300000) // 5-minute cache

    if (!user) {
      return NextResponse.json(
        { success: false, error: "User not found" },
        { status: 404 }
      )
    }

    // Calculate session duration - use sessionStartTime from JWT if available
    const sessionUser = session.user as any
    const sessionStartTime = sessionUser?.sessionStartTime 
      ? new Date(sessionUser.sessionStartTime) 
      : new Date(session.user.iat ? session.user.iat * 1000 : Date.now())
    const currentTime = new Date()
    const sessionDuration = Math.floor((currentTime.getTime() - sessionStartTime.getTime()) / 1000) // in seconds

    const profileData = {
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone || "",
      position: user.position || "",
      avatar: user.avatar || "",
      status: user.status,
      department: user.department,
      role: user.role,
      lastLogin: user.lastLogin,
      sessionDuration,
      sessionStartTime,
      address: user.address || {
        street: "",
        city: "",
        state: "",
        country: "",
        zipCode: "",
      },
      socialLinks: user.socialLinks || {
        linkedin: "",
        twitter: "",
        github: "",
      },
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      twoFactorEnabled: user.twoFactorEnabled,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    }

    return NextResponse.json({
      success: true,
      data: profileData
    })

  } catch (error: any) {
    console.error('Error in GET /api/profile:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// PUT /api/profile - Update current user's profile
export async function PUT(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: currentUser, userEmail } = await genericApiRoutesMiddleware(request, 'profile', 'update')

    const body = await request.json()
    
    // Check if it's a password change request
    if (body.currentPassword && body.newPassword) {
      return await handlePasswordChange(request, session.user.id, body)
    }

    // Validate profile data
    const validatedData = updateProfileSchema.safeParse(body)
    if (!validatedData.success) {
      return createErrorResponse(
        "Validation failed",
        400,
        validatedData.error.flatten().fieldErrors
      )
    }

    const user = await executeGenericDbQuery(async () => {
      return await User.findById(session.user.id)
    }, `user-${session.user.id}`, 60000) // 1-minute cache
    if (!user) {
      return createErrorResponse("User not found", 404)
    }

    // Update user profile
    const updateData = validatedData.data
    const updatedUser = await executeGenericDbQuery(async () => {
      return await User.findByIdAndUpdate(
        session.user.id,
        {
          ...updateData,
          'metadata.updatedBy': session.user.id,
          updatedAt: new Date(),
        },
        { new: true, runValidators: true }
      ).populate('role', 'name displayName').populate('department', 'name')
    })

    if (!updatedUser) {
      return createErrorResponse("Failed to update profile", 500)
    }

    // Log profile update
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'profile_update',
      resource: 'profile',
      details: { 
        message: 'Profile updated by user', 
        updatedFields: Object.keys(validatedData.data),
        userEmail: session.user.email!,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      message: "Profile updated successfully",
      data: {
        id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        phone: updatedUser.phone,
        position: updatedUser.position,
        avatar: updatedUser.avatar,
        address: updatedUser.address,
        socialLinks: updatedUser.socialLinks,
        updatedAt: updatedUser.updatedAt,
      }
    })

  } catch (error: any) {
    console.error('Error in PUT /api/profile:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

async function handlePasswordChange(request: NextRequest, userId: string, body: any) {
  try {
    const validatedData = changePasswordSchema.safeParse(body)
    if (!validatedData.success) {
      return NextResponse.json(
        {
          success: false,
          error: "Validation failed",
          details: validatedData.error.flatten().fieldErrors
        },
        { status: 400 }
      )
    }

    const { currentPassword, newPassword } = validatedData.data

    const user = await executeGenericDbQuery(async () => {
      return await User.findById(userId).select('+password')
    })
    if (!user) {
      return NextResponse.json(
        { success: false, error: "User not found" },
        { status: 404 }
      )
    }

    // Verify current password
    const isCurrentPasswordValid = await user.comparePassword(currentPassword)
    if (!isCurrentPasswordValid) {
      return NextResponse.json(
        { success: false, error: "Current password is incorrect" },
        { status: 400 }
      )
    }

    // Hash new password
    const saltRounds = 12
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds)

    // Update password
    await executeGenericDbQuery(async () => {
      return await User.findByIdAndUpdate(userId, {
        password: hashedPassword,
        passwordChangedAt: new Date(),
        'metadata.updatedBy': userId,
      })
    })

    // Log password change
    await AuditLogger.logUserAction({
      userId: userId,
      action: 'password_change',
      resource: 'profile',
      details: { 
        message: 'Password changed by user', 
        timestamp: new Date().toISOString(),
        userEmail: user.email,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      message: "Password changed successfully"
    })

  } catch (error: any) {
    console.error("Password change error:", error)
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 }
    )
  }
}