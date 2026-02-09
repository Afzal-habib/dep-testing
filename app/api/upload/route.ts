import { type NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { S3Service } from '@/lib/services/s3-service'

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// POST /api/upload - Upload file to S3
export async function POST(request: NextRequest) {
  try {
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'create')
    
    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const formData = await request.formData()
    const file = formData.get('file') as File | null
    const folder = formData.get('folder') as string || 'general'
    const channelId = formData.get('channelId') as string | null

    if (!file) {
      return createErrorResponse('No file provided', 400)
    }

    // Validate file type for images (channel avatars, profile pics)
    const allowedImageTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
    const allowedAudioTypes = ['audio/webm', 'audio/webm;codecs=opus', 'audio/ogg', 'audio/ogg;codecs=opus', 'audio/mp4', 'audio/mpeg', 'audio/wav', 'audio/mp3']
    const allowedTypes = [...allowedImageTypes, ...allowedAudioTypes]

    // Determine file category
    let fileType: 'PROFILE_PICTURES' | 'CHAT_ATTACHMENTS' = 'CHAT_ATTACHMENTS'
    if (folder === 'channel-avatars' || folder === 'profile-pictures') {
      fileType = 'PROFILE_PICTURES'
      if (!allowedImageTypes.includes(file.type)) {
        return createErrorResponse('Invalid file type. Only images are allowed for avatars.', 400)
      }
    }

    // Validate file size (5MB for avatars, 25MB for chat attachments)
    const maxSize = fileType === 'PROFILE_PICTURES' ? 5 * 1024 * 1024 : 25 * 1024 * 1024
    if (file.size > maxSize) {
      return createErrorResponse(`File too large. Maximum size is ${maxSize / (1024 * 1024)}MB`, 400)
    }

    // Convert file to buffer
    const arrayBuffer = await file.arrayBuffer()
    const buffer = Buffer.from(arrayBuffer)

    // Upload to S3
    const result = await S3Service.uploadFile({
      file: buffer,
      fileName: file.name,
      contentType: file.type,
      fileType: fileType,
      userId: session.user.id,
      metadata: {
        folder: folder,
        channelId: channelId || '',
        originalName: file.name
      }
    })

    if (!result.success) {
      return createErrorResponse(result.error || 'Upload failed', 500)
    }

    return NextResponse.json({
      success: true,
      url: result.data?.url,
      key: result.data?.key,
      size: result.data?.size,
      contentType: result.data?.contentType
    })
  } catch (error: any) {
    console.error('Upload error:', error)
    return createErrorResponse(error.message || 'Upload failed', 500)
  }
}
