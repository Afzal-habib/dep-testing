"use client"

/**
 * Generic Forward Service
 * Handles forwarding of messages and attachments to multiple channels
 * WhatsApp-style multi-select and batch forwarding
 */

import { IAttachment, IChannel } from "@/types/communication"

export interface ForwardItem {
  type: 'message' | 'attachment'
  id: string
  content?: string // For messages
  attachmentData?: IAttachment // For attachments
}

export interface ForwardRequest {
  items: ForwardItem[]
  targetChannelIds: string[]
  optionalMessage?: string
}

export interface ForwardResult {
  success: boolean
  channelId: string
  messageIds: string[]
  error?: string
}

export interface ForwardResponse {
  success: boolean
  results: ForwardResult[]
  totalForwarded: number
  totalFailed: number
}

/**
 * Forward messages to multiple channels
 */
export async function forwardMessages(
  messageIds: string[],
  targetChannelIds: string[],
  optionalMessage?: string
): Promise<ForwardResponse> {
  try {
    const response = await fetch('/api/communication/messages/forward', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messageIds,
        targetChannelIds,
        message: optionalMessage
      })
    })

    const data = await response.json()

    if (!response.ok) {
      throw new Error(data.error || 'Failed to forward messages')
    }

    return {
      success: true,
      results: data.data || [],
      totalForwarded: data.data?.length || 0,
      totalFailed: 0
    }
  } catch (error) {
    console.error('Forward messages error:', error)
    return {
      success: false,
      results: [],
      totalForwarded: 0,
      totalFailed: messageIds.length * targetChannelIds.length
    }
  }
}

/**
 * Forward attachments to multiple channels
 */
export async function forwardAttachments(
  attachmentIds: string[],
  targetChannelIds: string[],
  optionalMessage?: string
): Promise<ForwardResponse> {
  const results: ForwardResult[] = []
  let totalForwarded = 0
  let totalFailed = 0

  // Forward each attachment to all target channels
  for (const attachmentId of attachmentIds) {
    try {
      const response = await fetch('/api/communication/attachments', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attachmentId,
          targetChannelIds,
          message: optionalMessage
        })
      })

      const data = await response.json()

      if (response.ok && data.success) {
        results.push(...(data.data || []).map((r: any) => ({
          success: true,
          channelId: r.channelId,
          messageIds: [r.messageId]
        })))
        totalForwarded += targetChannelIds.length
      } else {
        totalFailed += targetChannelIds.length
      }
    } catch (error) {
      console.error(`Forward attachment ${attachmentId} error:`, error)
      totalFailed += targetChannelIds.length
    }
  }

  return {
    success: totalForwarded > 0,
    results,
    totalForwarded,
    totalFailed
  }
}

/**
 * Forward mixed items (messages and attachments) to multiple channels
 */
export async function forwardItems(
  request: ForwardRequest
): Promise<ForwardResponse> {
  const messageItems = request.items.filter(i => i.type === 'message')
  const attachmentItems = request.items.filter(i => i.type === 'attachment')

  const messageIds = messageItems.map(i => i.id)
  const attachmentIds = attachmentItems.map(i => i.id)

  const results: ForwardResult[] = []
  let totalForwarded = 0
  let totalFailed = 0

  // Forward messages
  if (messageIds.length > 0) {
    const msgResult = await forwardMessages(
      messageIds,
      request.targetChannelIds,
      request.optionalMessage
    )
    results.push(...msgResult.results)
    totalForwarded += msgResult.totalForwarded
    totalFailed += msgResult.totalFailed
  }

  // Forward attachments
  if (attachmentIds.length > 0) {
    const attResult = await forwardAttachments(
      attachmentIds,
      request.targetChannelIds,
      request.optionalMessage
    )
    results.push(...attResult.results)
    totalForwarded += attResult.totalForwarded
    totalFailed += attResult.totalFailed
  }

  return {
    success: totalForwarded > 0,
    results,
    totalForwarded,
    totalFailed
  }
}

/**
 * Copy attachment link to clipboard
 */
export async function copyAttachmentLink(attachment: IAttachment): Promise<boolean> {
  if (!attachment.file_url) return false
  
  try {
    await navigator.clipboard.writeText(attachment.file_url)
    return true
  } catch (error) {
    console.error('Copy failed:', error)
    return false
  }
}

/**
 * Download attachment
 */
export async function downloadAttachment(attachment: IAttachment): Promise<boolean> {
  if (!attachment.id) return false
  
  try {
    const response = await fetch(`/api/communication/attachments?download=${attachment.id}`)
    const data = await response.json()
    
    if (!data.success || !data.downloadUrl) {
      throw new Error('Failed to get download URL')
    }

    const a = document.createElement('a')
    a.href = data.downloadUrl
    a.download = attachment.file_name
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    
    return true
  } catch (error) {
    console.error('Download failed:', error)
    return false
  }
}

/**
 * Share via native share API (mobile/desktop)
 */
export async function nativeShare(
  attachment: IAttachment,
  title?: string
): Promise<boolean> {
  if (!navigator.share) return false
  
  try {
    await navigator.share({
      title: title || attachment.file_name,
      text: `Shared file: ${attachment.file_name}`,
      url: attachment.file_url || undefined
    })
    return true
  } catch (error) {
    // User cancelled or share failed
    return false
  }
}

/**
 * Share via email
 */
export function shareViaEmail(
  attachment: IAttachment,
  subject?: string,
  body?: string
): void {
  const emailSubject = subject || `Shared file: ${attachment.file_name}`
  const emailBody = body || `Here's a file I wanted to share with you:\n\n${attachment.file_name}\n${attachment.file_url || ''}`
  
  const mailtoUrl = `mailto:?subject=${encodeURIComponent(emailSubject)}&body=${encodeURIComponent(emailBody)}`
  window.open(mailtoUrl, '_blank')
}
