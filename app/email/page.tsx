'use client'

import { useState, useRef } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import RichTextEditor from '@/components/shared/rich-text-editor'
import { FileUpload } from '@/components/upload/file-upload'
import { useEmail } from '@/hooks/use-email'
import { EMAIL_CONSTANTS } from '@/lib/validations/email'
import { 
  Mail, 
  Send, 
  Users, 
  UserCheck, 
  EyeOff, 
  Paperclip, 
  TestTube, 
  AlertCircle,
  CheckCircle,
  Clock,
  X,
  Plus,
  Eye,
  Code
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'

interface S3EmailAttachment {
  key: string
  filename: string
  size: number
  contentType: string
  url?: string
}

interface EmailTemplate {
  name: string
  subject: string
  htmlContent: string
  textContent: string
  category: typeof EMAIL_CONSTANTS.CATEGORIES[number]
  priority: typeof EMAIL_CONSTANTS.PRIORITIES[number]
}

const EMAIL_TEMPLATES: EmailTemplate[] = [
  {
    name: 'Welcome Email',
    subject: 'Welcome to Digi Era Pro CRM!',
    htmlContent: `
      <h2>Welcome to Digi Era Pro CRM</h2>
      <p>Hello <strong>{{name}}</strong>,</p>
      <p>We're excited to have you on board! Your account has been successfully created.</p>
      <ul>
        <li>Access your dashboard</li>
        <li>Manage your projects</li>
        <li>Collaborate with your team</li>
      </ul>
      <p>If you have any questions, don't hesitate to reach out.</p>
      <p>Best regards,<br>The Digi Era Pro Team</p>
    `,
    textContent: 'Welcome to Digi Era Pro CRM!\n\nHello {{name}},\n\nWe\'re excited to have you on board! Your account has been successfully created.\n\n- Access your dashboard\n- Manage your projects\n- Collaborate with your team\n\nIf you have any questions, don\'t hesitate to reach out.\n\nBest regards,\nThe Digi Era Pro Team',
    category: 'auth',
    priority: 'normal'
  },
  {
    name: 'Password Reset',
    subject: 'Reset Your Digi Era Pro CRM Password',
    htmlContent: `
      <h2>Password Reset Request</h2>
      <p>Hello <strong>{{name}}</strong>,</p>
      <p>We received a request to reset your password for your Digi Era Pro CRM account.</p>
      <div style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 4px solid #007bff;">
        <p style="margin: 0;"><strong>Security Notice:</strong> If you didn't request this reset, please ignore this email.</p>
      </div>
      <p><a href="{{resetUrl}}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a></p>
      <p><small>This link will expire in 24 hours.</small></p>
      <p>Best regards,<br>The Digi Era Pro Security Team</p>
    `,
    textContent: 'Password Reset Request\n\nHello {{name}},\n\nWe received a request to reset your password for your Digi Era Pro CRM account.\n\nSECURITY NOTICE: If you didn\'t request this reset, please ignore this email.\n\nReset your password: {{resetUrl}}\n\nThis link will expire in 24 hours.\n\nBest regards,\nThe Digi Era Pro Security Team',
    category: 'auth',
    priority: 'high'
  },
  {
    name: 'Project Update',
    subject: 'Project Status Update - {{projectName}}',
    htmlContent: `
      <h2>Project Update: {{projectName}}</h2>
      <p>Hello team,</p>
      <p>Here's the latest update on <strong>{{projectName}}</strong>:</p>
      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background-color: #f8f9fa;">
          <td style="padding: 10px; border: 1px solid #dee2e6; font-weight: bold;">Status</td>
          <td style="padding: 10px; border: 1px solid #dee2e6;">{{status}}</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #dee2e6; font-weight: bold;">Progress</td>
          <td style="padding: 10px; border: 1px solid #dee2e6;">{{progress}}%</td>
        </tr>
        <tr style="background-color: #f8f9fa;">
          <td style="padding: 10px; border: 1px solid #dee2e6; font-weight: bold;">Next Milestone</td>
          <td style="padding: 10px; border: 1px solid #dee2e6;">{{nextMilestone}}</td>
        </tr>
      </table>
      <p>Keep up the great work!</p>
      <p>Best regards,<br>Project Management Team</p>
    `,
    textContent: 'Project Update: {{projectName}}\n\nHello team,\n\nHere\'s the latest update on {{projectName}}:\n\nStatus: {{status}}\nProgress: {{progress}}%\nNext Milestone: {{nextMilestone}}\n\nKeep up the great work!\n\nBest regards,\nProject Management Team',
    category: 'notification',
    priority: 'normal'
  },
  {
    name: 'System Maintenance',
    subject: '[URGENT] Scheduled System Maintenance - {{date}}',
    htmlContent: `
      <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
        <h2 style="color: #856404; margin-top: 0;">⚠️ Scheduled System Maintenance</h2>
      </div>
      <p>Dear Digi Era Pro CRM Users,</p>
      <p>We will be performing scheduled maintenance on our systems:</p>
      <ul>
        <li><strong>Date:</strong> {{date}}</li>
        <li><strong>Time:</strong> {{time}}</li>
        <li><strong>Duration:</strong> {{duration}}</li>
        <li><strong>Expected Impact:</strong> {{impact}}</li>
      </ul>
      <div style="background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; margin: 20px 0;">
        <p style="margin: 0;"><strong>What to expect:</strong></p>
        <p style="margin: 5px 0 0 0;">During this maintenance window, the CRM system will be temporarily unavailable. Please save your work and plan accordingly.</p>
      </div>
      <p>We apologize for any inconvenience and appreciate your understanding.</p>
      <p>Best regards,<br>Digi Era Pro IT Team</p>
    `,
    textContent: 'SCHEDULED SYSTEM MAINTENANCE\n\nDear Digi Era Pro CRM Users,\n\nWe will be performing scheduled maintenance on our systems:\n\nDate: {{date}}\nTime: {{time}}\nDuration: {{duration}}\nExpected Impact: {{impact}}\n\nWhat to expect:\nDuring this maintenance window, the CRM system will be temporarily unavailable. Please save your work and plan accordingly.\n\nWe apologize for any inconvenience and appreciate your understanding.\n\nBest regards,\nDepLLC IT Team',
    category: 'system',
    priority: 'urgent'
  }
]

export default function EmailTestingPage() {
  const [activeTab, setActiveTab] = useState('compose')
  const [toEmails, setToEmails] = useState<string[]>([])
  const [ccEmails, setCcEmails] = useState<string[]>([])
  const [bccEmails, setBccEmails] = useState<string[]>([])
  const [showCc, setShowCc] = useState(false)
  const [showBcc, setShowBcc] = useState(false)
  const [subject, setSubject] = useState('')
  const [htmlContent, setHtmlContent] = useState('')
  const [textContent, setTextContent] = useState('')
  const [category, setCategory] = useState<typeof EMAIL_CONSTANTS.CATEGORIES[number]>('notification')
  const [priority, setPriority] = useState<typeof EMAIL_CONSTANTS.PRIORITIES[number]>('normal')
  const [replyTo, setReplyTo] = useState('')
  const [s3Attachments, setS3Attachments] = useState<S3EmailAttachment[]>([])
  const [selectedTemplate, setSelectedTemplate] = useState<string>('')
  const [showPreview, setShowPreview] = useState(false)
  const [testResults, setTestResults] = useState<any[]>([])

  const { toast } = useToast()
  const richTextEditorRef = useRef<any>(null)

  const { 
    sendEmail, 
    validateEmailAddresses, 
    countTotalRecipients, 
    isLoading 
  } = useEmail()

  const addEmail = (type: 'to' | 'cc' | 'bcc', email: string) => {
    if (!email.trim() || !validateEmailAddresses(email)) {
      toast({
        title: "Invalid Email",
        description: "Please enter a valid email address",
        variant: "destructive"
      })
      return
    }

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
      ;(e.target as HTMLInputElement).value = ''
    }
  }

  const applyTemplate = (templateName: string) => {
    const template = EMAIL_TEMPLATES.find(t => t.name === templateName)
    if (template) {
      setSubject(template.subject)
      setHtmlContent(template.htmlContent)
      setTextContent(template.textContent)
      setCategory(template.category)
      setPriority(template.priority)

      // Update rich text editor content
      if (richTextEditorRef.current) {
        richTextEditorRef.current.getEditor()?.commands.setContent(template.htmlContent)
      }

      toast({
        title: "Template Applied",
        description: `Applied "${template.name}" template`,
        variant: "default"
      })
    }
  }

  const handleFilesUploaded = (files: any[]) => {
    const newAttachments: S3EmailAttachment[] = files.map(file => ({
      key: file.key,
      filename: file.originalName,
      size: file.size,
      contentType: file.contentType,
      url: file.url
    }))
    
    setS3Attachments(prev => [...prev, ...newAttachments])
    
    toast({
      title: "Attachments Added",
      description: `${files.length} file(s) uploaded successfully`,
      variant: "default"
    })
  }

  const removeAttachment = (index: number) => {
    setS3Attachments(prev => prev.filter((_, i) => i !== index))
  }

  const totalRecipients = countTotalRecipients({
    to: toEmails,
    cc: ccEmails,
    bcc: bccEmails
  })

  const handleSendEmail = async () => {
    try {
      if (toEmails.length === 0) {
        toast({
          title: "No Recipients",
          description: "Please add at least one recipient",
          variant: "destructive"
        })
        return
      }

      if (!subject.trim()) {
        toast({
          title: "No Subject",
          description: "Please enter an email subject",
          variant: "destructive"
        })
        return
      }

      if (!htmlContent.trim() && !textContent.trim()) {
        toast({
          title: "No Content",
          description: "Please enter email content (HTML or text)",
          variant: "destructive"
        })
        return
      }

      if (totalRecipients > EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT) {
        toast({
          title: "Too Many Recipients",
          description: `Total recipients cannot exceed ${EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT}`,
          variant: "destructive"
        })
        return
      }

      const emailData: any = {
        to: toEmails,
        cc: ccEmails.length > 0 ? ccEmails : undefined,
        bcc: bccEmails.length > 0 ? bccEmails : undefined,
        subject,
        htmlContent: htmlContent || undefined,
        textContent: textContent || undefined,
        category,
        priority,
        replyTo: replyTo || undefined
      }

      // Add S3 attachments if any
      if (s3Attachments.length > 0) {
        emailData.s3Attachments = s3Attachments
      }

      const result = await sendEmail(emailData)

      // Log test result
      const testResult = {
        id: Date.now(),
        timestamp: new Date().toLocaleString(),
        status: 'success',
        messageId: result.messageId,
        recipients: totalRecipients,
        attachments: s3Attachments.length,
        category,
        priority,
        subject
      }

      setTestResults(prev => [testResult, ...prev.slice(0, 9)]) // Keep last 10 results

      toast({
        title: "Email Sent Successfully!",
        description: `Email sent to ${totalRecipients} recipient(s)`,
        variant: "default"
      })

    } catch (error: any) {
      console.error('Failed to send email:', error)
      
      // Log error result
      const testResult = {
        id: Date.now(),
        timestamp: new Date().toLocaleString(),
        status: 'error',
        error: error.message,
        recipients: totalRecipients,
        attachments: s3Attachments.length,
        category,
        priority,
        subject
      }

      setTestResults(prev => [testResult, ...prev.slice(0, 9)])
    }
  }

  const clearForm = () => {
    setToEmails([])
    setCcEmails([])
    setBccEmails([])
    setSubject('')
    setHtmlContent('')
    setTextContent('')
    setS3Attachments([])
    setReplyTo('')
    setShowCc(false)
    setShowBcc(false)
    setSelectedTemplate('')
    
    if (richTextEditorRef.current) {
      richTextEditorRef.current.getEditor()?.commands.setContent('')
    }

    toast({
      title: "Form Cleared",
      description: "All form fields have been reset",
      variant: "default"
    })
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
          placeholder={placeholder}
          className="border-0 shadow-none flex-1 min-w-[200px] focus-visible:ring-0"
          onKeyDown={(e) => handleKeyPress(e, type, e.currentTarget.value)}
          onBlur={(e) => {
            if (e.target.value.trim()) {
              addEmail(type, e.target.value)
              e.target.value = ''
            }
          }}
        />
      </div>
    </div>
  )

  return (
    <div className="container mx-auto py-8 px-4 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
          <TestTube className="h-8 w-8" />
          Email Service Testing Page
        </h1>
        <p className="text-muted-foreground">
          Comprehensive testing interface for AWS SES email functionality with rich text editing and S3 attachments
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Email Composer */}
        <div className="lg:col-span-2">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="compose" className="flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Compose
              </TabsTrigger>
              <TabsTrigger value="templates" className="flex items-center gap-2">
                <Code className="h-4 w-4" />
                Templates
              </TabsTrigger>
              <TabsTrigger value="preview" className="flex items-center gap-2">
                <Eye className="h-4 w-4" />
                Preview
              </TabsTrigger>
            </TabsList>

            <TabsContent value="compose" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Send className="h-5 w-5" />
                    Email Composer
                  </CardTitle>
                  <CardDescription>
                    Compose and send test emails with rich text editing and attachments
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
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

                  <Separator />

                  {/* Subject */}
                  <div>
                    <Label htmlFor="subject">Subject *</Label>
                    <Input
                      id="subject"
                      value={subject}
                      onChange={(e) => setSubject(e.target.value)}
                      placeholder="Email subject..."
                      maxLength={EMAIL_CONSTANTS.SUBJECT.MAX_LENGTH}
                    />
                    <div className="text-xs text-muted-foreground mt-1">
                      {subject.length}/{EMAIL_CONSTANTS.SUBJECT.MAX_LENGTH} characters
                    </div>
                  </div>

                  {/* Email Options */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <Label htmlFor="category">Category</Label>
                      <Select value={category} onValueChange={(value: any) => setCategory(value)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select category" />
                        </SelectTrigger>
                        <SelectContent>
                          {EMAIL_CONSTANTS.CATEGORIES.map((cat) => (
                            <SelectItem key={cat} value={cat}>
                              {cat.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="priority">Priority</Label>
                      <Select value={priority} onValueChange={(value: any) => setPriority(value)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select priority" />
                        </SelectTrigger>
                        <SelectContent>
                          {EMAIL_CONSTANTS.PRIORITIES.map((prio) => (
                            <SelectItem key={prio} value={prio}>
                              {prio.charAt(0).toUpperCase() + prio.slice(1)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="replyTo">Reply To</Label>
                      <Input
                        id="replyTo"
                        value={replyTo}
                        onChange={(e) => setReplyTo(e.target.value)}
                        placeholder="reply@example.com"
                        type="email"
                      />
                    </div>
                  </div>

                  <Separator />

                  {/* Rich Text Content */}
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="htmlContent">HTML Content (Rich Text Editor)</Label>
                      <RichTextEditor
                        ref={richTextEditorRef}
                        value={htmlContent}
                        onChange={setHtmlContent}
                        placeholder="Enter your email content with rich formatting..."
                        height="300px"
                        className="mt-2"
                      />
                    </div>

                    <div>
                      <Label htmlFor="textContent">Plain Text Content (Fallback)</Label>
                      <Textarea
                        id="textContent"
                        value={textContent}
                        onChange={(e) => setTextContent(e.target.value)}
                        placeholder="Plain text version of your email..."
                        rows={6}
                        maxLength={EMAIL_CONSTANTS.CONTENT.MAX_LENGTH}
                      />
                      <div className="text-xs text-muted-foreground mt-1">
                        {textContent.length}/{EMAIL_CONSTANTS.CONTENT.MAX_LENGTH} characters
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* S3 Attachments */}
                  <div className="space-y-4">
                    <Label className="flex items-center gap-2">
                      <Paperclip className="h-4 w-4" />
                      Email Attachments (S3)
                    </Label>
                    
                    <FileUpload
                      fileType="EMAIL_ATTACHMENTS"
                      multiple={true}
                      maxFiles={10}
                      onFilesUploaded={handleFilesUploaded}
                      className="min-h-[120px]"
                    />

                    {s3Attachments.length > 0 && (
                      <div className="space-y-2">
                        <Label>Current Attachments ({s3Attachments.length})</Label>
                        <div className="space-y-2">
                          {s3Attachments.map((attachment, index) => (
                            <div key={index} className="flex items-center justify-between p-2 border rounded">
                              <div className="flex items-center gap-2">
                                <Paperclip className="h-4 w-4" />
                                <span className="text-sm font-medium">{attachment.filename}</span>
                                <Badge variant="secondary" className="text-xs">
                                  {(attachment.size / 1024 / 1024).toFixed(2)} MB
                                </Badge>
                              </div>
                              <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                onClick={() => removeAttachment(index)}
                                className="h-6 w-6 p-0 hover:bg-destructive hover:text-destructive-foreground"
                              >
                                <X className="h-3 w-3" />
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <Separator />

                  {/* Action Buttons */}
                  <div className="flex gap-2">
                    <Button 
                      onClick={handleSendEmail}
                      disabled={isLoading || totalRecipients === 0}
                      className="flex-1"
                    >
                      {isLoading ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                          Sending...
                        </>
                      ) : (
                        <>
                          <Send className="h-4 w-4 mr-2" />
                          Send Test Email ({totalRecipients})
                        </>
                      )}
                    </Button>
                    <Button 
                      variant="outline" 
                      onClick={clearForm}
                      disabled={isLoading}
                    >
                      Clear Form
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="templates" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Email Templates</CardTitle>
                  <CardDescription>
                    Pre-defined email templates for common use cases
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {EMAIL_TEMPLATES.map((template) => (
                      <Card key={template.name} className="cursor-pointer hover:bg-accent/50 transition-colors">
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between">
                            <div className="space-y-2 flex-1">
                              <div className="flex items-center gap-2">
                                <h4 className="font-semibold">{template.name}</h4>
                                <Badge variant="outline">{template.category}</Badge>
                                <Badge 
                                  variant={template.priority === 'urgent' ? 'destructive' : 
                                          template.priority === 'high' ? 'secondary' : 'default'}
                                >
                                  {template.priority}
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground">{template.subject}</p>
                              <p className="text-xs text-muted-foreground line-clamp-2">
                                {template.textContent.slice(0, 150)}...
                              </p>
                            </div>
                            <Button
                              size="sm"
                              onClick={() => {
                                applyTemplate(template.name)
                                setActiveTab('compose')
                              }}
                            >
                              Apply Template
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="preview" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Email Preview</CardTitle>
                  <CardDescription>
                    Preview how your email will look to recipients
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {subject || htmlContent || textContent ? (
                    <div className="space-y-4">
                      <div className="border rounded-lg p-4 bg-background">
                        <div className="border-b pb-4 mb-4">
                          <div className="space-y-2 text-sm">
                            <div><strong>From:</strong> {process.env.NEXT_PUBLIC_FROM_EMAIL || 'noreply@depllc.com'}</div>
                            <div><strong>To:</strong> {toEmails.join(', ') || 'No recipients'}</div>
                            {ccEmails.length > 0 && <div><strong>CC:</strong> {ccEmails.join(', ')}</div>}
                            {bccEmails.length > 0 && <div><strong>BCC:</strong> {bccEmails.join(', ')}</div>}
                            {replyTo && <div><strong>Reply-To:</strong> {replyTo}</div>}
                            <div><strong>Subject:</strong> {subject || 'No subject'}</div>
                            <div className="flex items-center gap-2">
                              <Badge variant="outline">{category}</Badge>
                              <Badge variant="secondary">{priority}</Badge>
                            </div>
                          </div>
                        </div>
                        
                        {htmlContent ? (
                          <div 
                            className="prose prose-sm max-w-none"
                            dangerouslySetInnerHTML={{ __html: htmlContent }}
                          />
                        ) : textContent ? (
                          <pre className="whitespace-pre-wrap text-sm">{textContent}</pre>
                        ) : (
                          <p className="text-muted-foreground italic">No content to preview</p>
                        )}

                        {s3Attachments.length > 0 && (
                          <div className="border-t pt-4 mt-4">
                            <div className="text-sm font-medium mb-2">Attachments ({s3Attachments.length}):</div>
                            <div className="space-y-1">
                              {s3Attachments.map((attachment, index) => (
                                <div key={index} className="flex items-center gap-2 text-sm">
                                  <Paperclip className="h-3 w-3" />
                                  {attachment.filename}
                                  <Badge variant="outline" className="text-xs">
                                    {(attachment.size / 1024 / 1024).toFixed(2)} MB
                                  </Badge>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Mail className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No email content to preview</p>
                      <p className="text-sm">Compose an email to see the preview</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Test Results */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TestTube className="h-5 w-5" />
                Test Results
              </CardTitle>
              <CardDescription>
                Recent email sending test results
              </CardDescription>
            </CardHeader>
            <CardContent>
              {testResults.length > 0 ? (
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {testResults.map((result) => (
                    <div key={result.id} className="border rounded-lg p-3">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {result.status === 'success' ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : (
                            <AlertCircle className="h-4 w-4 text-destructive" />
                          )}
                          <Badge 
                            variant={result.status === 'success' ? 'default' : 'destructive'}
                            className="text-xs"
                          >
                            {result.status}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {result.timestamp}
                        </div>
                      </div>
                      
                      <div className="space-y-1 text-sm">
                        <div className="font-medium truncate">{result.subject}</div>
                        <div className="text-muted-foreground">
                          {result.recipients} recipient(s)
                          {result.attachments > 0 && `, ${result.attachments} attachment(s)`}
                        </div>
                        {result.messageId && (
                          <div className="text-xs text-muted-foreground font-mono">
                            ID: {result.messageId.slice(0, 20)}...
                          </div>
                        )}
                        {result.error && (
                          <div className="text-xs text-destructive">{result.error}</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <TestTube className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No test results yet</p>
                  <p className="text-xs">Send an email to see results</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Email Statistics */}
          <Card>
            <CardHeader>
              <CardTitle>Email Statistics</CardTitle>
              <CardDescription>
                Current email configuration limits
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 text-sm">
                <div className="flex justify-between">
                  <span>Max Recipients (Total):</span>
                  <Badge>{EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT}</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Max Recipients (Per Field):</span>
                  <Badge>{EMAIL_CONSTANTS.RECIPIENTS.MAX_COUNT}</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Max Subject Length:</span>
                  <Badge>{EMAIL_CONSTANTS.SUBJECT.MAX_LENGTH}</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Max Content Length:</span>
                  <Badge>{(EMAIL_CONSTANTS.CONTENT.MAX_LENGTH / 1000).toFixed(0)}KB</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Max Attachments:</span>
                  <Badge>{EMAIL_CONSTANTS.ATTACHMENT.MAX_COUNT}</Badge>
                </div>
                <div className="flex justify-between">
                  <span>Max Attachment Size:</span>
                  <Badge>{EMAIL_CONSTANTS.ATTACHMENT.MAX_SIZE / 1024 / 1024}MB</Badge>
                </div>
                
                <Separator />
                
                <div className="space-y-2">
                  <div className="font-medium">Supported Categories:</div>
                  <div className="flex flex-wrap gap-1">
                    {EMAIL_CONSTANTS.CATEGORIES.map(cat => (
                      <Badge key={cat} variant="outline" className="text-xs">
                        {cat.replace('-', ' ')}
                      </Badge>
                    ))}
                  </div>
                </div>
                
                <div className="space-y-2">
                  <div className="font-medium">Priority Levels:</div>
                  <div className="flex flex-wrap gap-1">
                    {EMAIL_CONSTANTS.PRIORITIES.map(prio => (
                      <Badge key={prio} variant="secondary" className="text-xs">
                        {prio}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="w-full justify-start"
                  onClick={() => {
                    setToEmails(['test@example.com'])
                    setSubject('Test Email from Digi Era Pro CRM')
                    setHtmlContent('<p>This is a test email from the Digi Era Pro CRM system.</p>')
                    setTextContent('This is a test email from the Digi Era Pro CRM system.')
                    setActiveTab('compose')
                  }}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Quick Test Email
                </Button>
                
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="w-full justify-start"
                  onClick={() => {
                    applyTemplate('Welcome Email')
                    setActiveTab('compose')
                  }}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Load Welcome Template
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
