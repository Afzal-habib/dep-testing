"use client"

import { useState, useRef, useImperativeHandle, forwardRef } from "react"
import { cn } from "@/lib/utils"
import { CreateMessageData, ICommunication, IChannelMember, IAttachment } from "@/types/communication"
import { useToast } from "@/hooks/use-toast"
import {
  TooltipProvider,
} from "@/components/ui/tooltip"
import RichMessageEditor, { RichMessageEditorRef } from "./rich-message-editor"

export interface MessageInputRef {
  setReplyTo: (message: ICommunication | null) => void
  setEditMessage: (message: ICommunication | null) => void
  focus: () => void
}

interface MessageInputProps {
  channelId: string
  onSend: (data: CreateMessageData) => Promise<void>
  onSendWithFiles?: (data: CreateMessageData, files: File[], onProgress?: (progress: number) => void) => Promise<any>
  onSendVoice?: (audioBlob: Blob, duration: number) => Promise<void>
  onEdit?: (messageId: string, data: CreateMessageData, newFiles?: File[], attachmentsToRemove?: string[]) => Promise<void>
  existingAttachments?: IAttachment[] // Existing attachments for editing
  disabled?: boolean
  placeholder?: string
  allowAttachments?: boolean
  maxLength?: number
  className?: string
  onTyping?: () => void
  onStopTyping?: () => void
  channelMembers?: IChannelMember[]
  channelType?: string
}

export const MessageInput = forwardRef<MessageInputRef, MessageInputProps>(({
  channelId,
  onSend,
  onSendWithFiles,
  onSendVoice,
  onEdit,
  disabled = false,
  placeholder = "Type a message...",
  allowAttachments = true,
  maxLength = 5000,
  className,
  onTyping,
  onStopTyping,
  channelMembers = [],
  channelType,
  existingAttachments
}, ref) => {
  const [messageHtml, setMessageHtml] = useState("")
  const [messageText, setMessageText] = useState("")
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [replyTo, setReplyTo] = useState<ICommunication | null>(null)
  const [editMessage, setEditMessage] = useState<ICommunication | null>(null)
  
  const editorRef = useRef<RichMessageEditorRef | null>(null)
  
  const { toast } = useToast()

  // Expose methods to parent
  useImperativeHandle(ref, () => ({
    setReplyTo: (message: ICommunication | null) => {
      setReplyTo(message)
      setEditMessage(null)
      editorRef.current?.focus()
    },
    setEditMessage: (message: ICommunication | null) => {
      setEditMessage(message)
      setReplyTo(null)
      if (message) {
        editorRef.current?.setEditMessage(message)
      }
    },
    focus: () => {
      editorRef.current?.focus()
    }
  }))

  // Handler the editor will call when it wants to send a message
  const handleSendFromEditor = async (
    html: string, 
    text: string, 
    files: File[],
    mentionedUserIds: string[] = [],
    replyToId?: string,
    editMessageId?: string,
    attachmentsToRemove?: string[]
  ) => {
    if ((!text || text.trim().length === 0) && files.length === 0) return false
    if (disabled || isUploading) return false

    try {
      const contentToSend = html && html.trim().length > 0 ? html.trim() : (text || "").trim()

      const messageData: CreateMessageData = {
        channel_id: channelId,
        content: contentToSend,
        content_type: files.length > 0 ? 'file' : 'text',
        mongo_mentioned_user_ids: mentionedUserIds.length > 0 ? mentionedUserIds : undefined,
        parent_message_id: replyToId
      }

      if (editMessageId && onEdit) {
        // Handle edit - await for synchronous update
        await onEdit(editMessageId, messageData, files, attachmentsToRemove)
        // Clear state
        setReplyTo(null)
        setEditMessage(null)
        return true
      } else if (files.length > 0 && onSendWithFiles) {
        // Handle new message with files - await for upload
        setIsUploading(true)
        setUploadProgress(0)
        try {
          await onSendWithFiles(messageData, files, (progress) => {
            setUploadProgress(progress)
          })
          // Clear state
          setReplyTo(null)
          setEditMessage(null)
          return true
        } finally {
          setIsUploading(false)
          setUploadProgress(0)
        }
      } else {
        // Handle new text message - send in background for realtime experience
        onSend(messageData).catch((_error) => {
          toast({
            title: "Error",
            description: "Failed to send message",
            variant: "destructive"
          })
        })
        // Clear state immediately
        setReplyTo(null)
        setEditMessage(null)
        return true
      }
    } catch {
      toast({
        title: "Error",
        description: editMessageId ? "Failed to update message" : "Failed to send message",
        variant: "destructive"
      })
      return false
    }
  }

  return (
    <TooltipProvider>
      <div className={cn("border-t bg-card p-2", className)}>
        {/* Upload progress indicator */}
        {isUploading && (
          <div className="mb-2 px-2">
            <div className="flex items-center justify-between text-xs text-muted-foreground mb-1">
              <span>Uploading files...</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="h-1 bg-muted rounded-full overflow-hidden">
              <div 
                className="h-full bg-primary transition-all duration-300"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}
        
        {/* Input area */}
        <div className="flex items-end gap-2">
          {/* Rich Text Editor */}
          <div className="flex-1">
            <RichMessageEditor
              ref={editorRef}
              value={messageHtml}
              placeholder={placeholder}
              disabled={disabled || isUploading}
              maxLength={maxLength}
              onChange={(html, text) => {
                setMessageHtml(html)
                setMessageText(text)
              }}
              onTyping={onTyping}
              onStopTyping={onStopTyping}
              onSend={handleSendFromEditor}
              onSendVoice={onSendVoice}
              channelMembers={channelMembers}
              replyTo={replyTo}
              editMessage={editMessage}
              existingAttachments={existingAttachments}
              onAttachmentRemove={(attachmentId) => {
                // This will be handled by the parent component
                // Attachment removal is delegated to parent's onAttachmentRemove prop
              }}
              onCancelReply={() => setReplyTo(null)}
              onCancelEdit={() => setEditMessage(null)}
              channelType={channelType}
            />
          </div>
        </div>

        {/* Keyboard shortcut hint */}
        <div className="mt-1 text-xs text-muted-foreground">
          Press Enter to send, Shift + Enter for new line (or new list item)
        </div>
      </div>
    </TooltipProvider>
  )
})

MessageInput.displayName = 'MessageInput'