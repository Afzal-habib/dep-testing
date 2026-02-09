'use client'

import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { useEmail } from '@/hooks/use-email'
import { EMAIL_CONSTANTS } from '@/lib/validations/email'
import { Badge } from '@/components/ui/badge'
import { X, Plus, Send, Users, UserCheck, EyeOff, Paperclip } from 'lucide-react'
import { EmailAttachmentSelector } from './email-attachment-selector'
import type { S3EmailAttachment } from '@/lib/validations/s3'

const emailComposerSchema = z.object({
  to: z.string().min(1, 'At least one recipient is required'),
  cc: z.string().optional(),
  bcc: z.string().optional(),
  subject: z.string().min(1, 'Subject is required').max(200),
  htmlContent: z.string().optional(),
  textContent: z.string().optional(),
  category: z.enum(EMAIL_CONSTANTS.CATEGORIES),
  priority: z.enum(EMAIL_CONSTANTS.PRIORITIES).default('normal'),
  replyTo: z.string().email().optional().or(z.literal(''))
}).refine((data) => data.htmlContent || data.textContent, {
  message: 'Either HTML content or text content is required',
  path: ['content']
})

type EmailComposerForm = z.infer<typeof emailComposerSchema>

interface EmailComposerProps {
  onEmailSent?: () => void
  defaultCategory?: typeof EMAIL_CONSTANTS.CATEGORIES[number]
  defaultTo?: string
  defaultSubject?: string
}

export function EmailComposer({
  onEmailSent,
  defaultCategory = 'notification',
  defaultTo = '',
  defaultSubject = ''
}: EmailComposerProps) {
  const [toEmails, setToEmails] = useState<string[]>(defaultTo ? [defaultTo] : [])
  const [ccEmails, setCcEmails] = useState<string[]>([])
  const [bccEmails, setBccEmails] = useState<string[]>([])
  const [showCc, setShowCc] = useState(false)
  const [s3Attachments, setS3Attachments] = useState<S3EmailAttachment[]>([])
  const [showBcc, setShowBcc] = useState(false)

  const {
    sendEmail,
    validateEmailAddresses,
    countTotalRecipients,
    isLoading
  } = useEmail()

  const form = useForm<EmailComposerForm>({
    resolver: zodResolver(emailComposerSchema),
    defaultValues: {
      to: defaultTo,
      subject: defaultSubject,
      category: defaultCategory,
      priority: 'normal',
      htmlContent: '',
      textContent: '',
      cc: '',
      bcc: '',
      replyTo: ''
    }
  })

  const addEmail = (type: 'to' | 'cc' | 'bcc', email: string) => {
    if (!email.trim() || !validateEmailAddresses(email)) return

    const setEmails = type === 'to' ? setToEmails : type === 'cc' ? setCcEmails : setBccEmails
    const emails = type === 'to' ? toEmails : type === 'cc' ? ccEmails : bccEmails

    if (!emails.includes(email.trim())) {
      setEmails([...emails, email.trim()])
    }
  }

  const removeEmail = (type: 'to' | 'cc' | 'bcc', index: number) => {
    const setEmails = type === 'to' ? setToEmails : type === 'cc' ? setCcEmails : setBccEmails
    const emails = type === 'to' ? toEmails : type === 'cc' ? ccEmails : bccEmails

    const newEmails = emails.filter((_, i) => i !== index)
    setEmails(newEmails)
  }

  const handleKeyPress = (e: React.KeyboardEvent, type: 'to' | 'cc' | 'bcc', value: string) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      addEmail(type, value)
      form.setValue(type, '')
    }
  }

  const totalRecipients = countTotalRecipients({
    to: toEmails,
    cc: ccEmails,
    bcc: bccEmails
  })

  const onSubmit = async (data: EmailComposerForm) => {
    try {
      // Validate we have recipients
      if (toEmails.length === 0) {
        form.setError('to', { message: 'At least one recipient is required' })
        return
      }

      // Check total recipient limit
      if (totalRecipients > EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT) {
        form.setError('to', {
          message: `Total recipients cannot exceed ${EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT}`
        })
        return
      }

      // Prepare email data with S3 attachments
      const emailData: any = {
        to: toEmails,
        cc: ccEmails.length > 0 ? ccEmails : undefined,
        bcc: bccEmails.length > 0 ? bccEmails : undefined,
        subject: data.subject,
        htmlContent: data.htmlContent || undefined,
        textContent: data.textContent || undefined,
        category: data.category,
        priority: data.priority,
        replyTo: data.replyTo || undefined
      }

      // Add S3 attachments if any
      if (s3Attachments.length > 0) {
        emailData.s3Attachments = s3Attachments
      }

      // Send email (API will automatically choose the right service based on attachments)
      await fetch('/api/email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(emailData)
      }).then(async (response) => {
        if (!response.ok) {
          const errorData = await response.json()
          throw new Error(errorData.error || 'Failed to send email')
        }
        return response.json()
      })

      // Reset form
      form.reset()
      setToEmails([])
      setCcEmails([])
      setBccEmails([])
      setS3Attachments([])
      setShowCc(false)
      setShowBcc(false)

      onEmailSent?.()
    } catch (error) {
      console.error('Failed to send email:', error)
    }
  }

  const EmailInputField = ({
    type,
    emails,
    placeholder
  }: {
    type: 'to' | 'cc' | 'bcc'
    emails: string[]
    placeholder: string
  }) => (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1 min-h-[32px] p-2 border rounded-md">
        {emails.map((email, index) => (
          <Badge key={index} variant="secondary" className="flex items-center gap-1">
            {email}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-4 w-4 p-0 hover:bg-destructive hover:text-destructive-foreground"
              onClick={() => removeEmail(type, index)}
            >
              <X className="h-3 w-3" />
            </Button>
          </Badge>
        ))}
        <Input
          {...form.register(type)}
          placeholder={placeholder}
          className="border-0 shadow-none flex-1 min-w-[200px] focus-visible:ring-0"
          onKeyDown={(e) => handleKeyPress(e, type, form.getValues(type) || '')}
          onBlur={(e) => {
            if (e.target.value.trim()) {
              addEmail(type, e.target.value)
              form.setValue(type, '')
            }
          }}
        />
      </div>
      {form.formState.errors[type] && (
        <p className="text-sm text-destructive">{form.formState.errors[type]?.message}</p>
      )}
    </div>
  )

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Send className="h-5 w-5" />
          Compose Email
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          {/* Recipients */}
          <div className="space-y-4">
            <div>
              <Label className="flex items-center gap-2">
                <Users className="h-4 w-4" />
                To *
              </Label>
              <EmailInputField
                type="to"
                emails={toEmails}
                placeholder="Enter email addresses..."
              />
            </div>

            {/* CC/BCC Controls */}
            <div className="flex gap-2">
              {!showCc && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setShowCc(true)}
                  className="flex items-center gap-1"
                >
                  <UserCheck className="h-3 w-3" />
                  Add CC
                </Button>
              )}
              {!showBcc && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setShowBcc(true)}
                  className="flex items-center gap-1"
                >
                  <EyeOff className="h-3 w-3" />
                  Add BCC
                </Button>
              )}
            </div>

            {showCc && (
              <div>
                <Label className="flex items-center gap-2">
                  <UserCheck className="h-4 w-4" />
                  CC
                </Label>
                <EmailInputField
                  type="cc"
                  emails={ccEmails}
                  placeholder="Carbon copy recipients..."
                />
              </div>
            )}

            {showBcc && (
              <div>
                <Label className="flex items-center gap-2">
                  <EyeOff className="h-4 w-4" />
                  BCC
                </Label>
                <EmailInputField
                  type="bcc"
                  emails={bccEmails}
                  placeholder="Blind carbon copy recipients..."
                />
              </div>
            )}

            {/* Recipient count */}
            <div className="text-sm text-muted-foreground">
              Total recipients: {totalRecipients}/{EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT}
            </div>
          </div>

          {/* Subject */}
          <div>
            <Label htmlFor="subject">Subject *</Label>
            <Input
              id="subject"
              {...form.register('subject')}
              placeholder="Email subject..."
            />
            {form.formState.errors.subject && (
              <p className="text-sm text-destructive mt-1">
                {form.formState.errors.subject.message}
              </p>
            )}
          </div>

          {/* Email Options */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <Label htmlFor="category">Category</Label>
              <Select
                value={form.watch('category')}
                onValueChange={(value) => form.setValue('category', value as any)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select category" />
                </SelectTrigger>
                <SelectContent>
                  {EMAIL_CONSTANTS.CATEGORIES.map((category) => (
                    <SelectItem key={category} value={category}>
                      {category.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="priority">Priority</Label>
              <Select
                value={form.watch('priority')}
                onValueChange={(value) => form.setValue('priority', value as any)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select priority" />
                </SelectTrigger>
                <SelectContent>
                  {EMAIL_CONSTANTS.PRIORITIES.map((priority) => (
                    <SelectItem key={priority} value={priority}>
                      {priority.charAt(0).toUpperCase() + priority.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="replyTo">Reply To</Label>
              <Input
                id="replyTo"
                {...form.register('replyTo')}
                placeholder="reply@example.com"
                type="email"
              />
            </div>
          </div>

          {/* Content */}
          <div className="space-y-4">
            <div>
              <Label htmlFor="htmlContent">HTML Content</Label>
              <Textarea
                id="htmlContent"
                {...form.register('htmlContent')}
                placeholder="HTML email content..."
                rows={8}
                className="font-mono text-sm"
              />
            </div>

            <div>
              <Label htmlFor="textContent">Text Content</Label>
              <Textarea
                id="textContent"
                {...form.register('textContent')}
                placeholder="Plain text email content..."
                rows={6}
              />
            </div>

            {(form.formState.errors as Record<string, { message?: string }>).content && (
              <p className="text-sm text-destructive">
                {(form.formState.errors as Record<string, { message?: string }>).content?.message}
              </p>
            )}
          </div>

          {/* Attachments */}
          <div className="space-y-4">
            <Separator />
            <div>
              <Label className="flex items-center gap-2">
                <Paperclip className="h-4 w-4" />
                Email Attachments
              </Label>
              <p className="text-sm text-muted-foreground mb-4">
                Upload files to attach to this email. Files are stored securely in AWS S3.
              </p>
              <EmailAttachmentSelector
                attachments={s3Attachments}
                onAttachmentsChange={setS3Attachments}
                maxAttachments={10}
                disabled={isLoading}
              />
            </div>
          </div>

          {/* Submit */}
          <Button
            type="submit"
            disabled={isLoading || totalRecipients === 0}
            className="w-full"
          >
            {isLoading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                Sending Email...
              </>
            ) : (
              <>
                <Send className="h-4 w-4 mr-2" />
                Send Email to {totalRecipients} recipient{totalRecipients !== 1 ? 's' : ''}
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}