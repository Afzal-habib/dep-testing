"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { MessageList } from "@/components/communication/message-list"
import { MessageInput } from "@/components/communication/message-input"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import {
  MessageSquare,
  Phone,
  Mail,
  Clock,
  CheckCircle,
  AlertCircle,
  HelpCircle
} from "lucide-react"
import { cn } from "@/lib/utils"
import { CreateMessageData, ICommunication } from "@/types/communication"
import { useCommunications } from "@/hooks/use-communications"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"

export default function ClientChatPage() {
  const [supportTicketStatus] = useState<'open' | 'in-progress' | 'resolved'>('in-progress')

  const {
    channels,
    messages,
    messagesLoading,
    actionLoading,
    error,
    currentUser,
    typingUsers,
    sendMessage,
    markAsRead,
    setTyping,
    removeTyping,
    fetchChannels,
    selectChannel
  } = useCommunications()

  // Find client support channel
  const supportChannel = channels.find(ch => ch.type === 'client-support')

  useEffect(() => {
    if (channels.length === 0) {
      fetchChannels()
    }
  }, [channels.length, fetchChannels])

  useEffect(() => {
    if (supportChannel) {
      selectChannel(supportChannel.id)
    }
  }, [supportChannel, selectChannel])

  // Mock client data (in real app, this would come from auth/context)
  const clientInfo = {
    name: 'Zaid Khan',
    email: 'mike@client.com',
    company: 'Client Corporation',
    accountManager: {
      name: 'Afzal Habib',
      role: 'Account Manager',
      email: 'afzal@depllc.com',
      avatar: '/profile-image.jpg',
      isOnline: true
    },
    subscription: 'Premium Plan',
    supportPriority: 'standard' as const
  }

  const handleSendMessage = async (messageData: CreateMessageData) => {
    try {
      await sendMessage({
        ...messageData,
        content_type: 'text',
      })
    } catch (error) {
      console.error('Failed to send message:', error)
    }
  }

  const handleMessageRead = (messageId: string) => {
    if (supportChannel) {
      markAsRead(messageId, supportChannel.id)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open':
        return <AlertCircle className="h-4 w-4 text-orange-500" />
      case 'in-progress':
        return <Clock className="h-4 w-4 text-blue-500" />
      case 'resolved':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      default:
        return <HelpCircle className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'in-progress': return 'bg-blue-100 text-blue-800 border-blue-200'
      case 'resolved': return 'bg-green-100 text-green-800 border-green-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Client Portal Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-8xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center gap-4">
              <div className="h-8 w-8 bg-primary rounded-lg flex items-center justify-center">
                <MessageSquare className="h-5 w-5 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900">Support Chat</h1>
                <p className="text-sm text-gray-500">Get help from our support team</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <Badge variant="outline" className="text-sm">
                {clientInfo.subscription}
              </Badge>

              <div className="text-right text-sm">
                <p className="font-medium text-gray-900">{clientInfo.name}</p>
                <p className="text-gray-500">{clientInfo.company}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-8xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 h-[calc(100vh-200px)]">
          {/* Sidebar - Support Info */}
          <div className="lg:col-span-1 space-y-4">
            {/* Support Status */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  {getStatusIcon(supportTicketStatus)}
                  Support Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Badge
                  variant="outline"
                  className={cn("w-full justify-center", getStatusColor(supportTicketStatus))}
                >
                  {supportTicketStatus.charAt(0).toUpperCase() + supportTicketStatus.slice(1).replace('-', ' ')}
                </Badge>

                <div className="mt-4 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Priority:</span>
                    <Badge variant="secondary">{clientInfo.supportPriority}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Response Time:</span>
                    <span>~2 hours</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Account Manager */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Your Account Manager</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-start gap-3">
                  <div className="relative">
                    <Avatar className="h-10 w-10">
                      <AvatarImage src={clientInfo.accountManager.avatar} alt={clientInfo.accountManager.name} />
                      <AvatarFallback>
                        {clientInfo.accountManager.name
                          ? (() => {
                            const parts = clientInfo.accountManager.name.trim().split(' ');
                            if (parts.length === 1) {
                              return parts[0][0].toUpperCase();
                            }
                            return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                          })()
                          : ''}
                      </AvatarFallback>
                    </Avatar>
                    {clientInfo.accountManager.isOnline && (
                      <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-500 border-2 border-white" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm">{clientInfo.accountManager.name}</p>
                    <p className="text-xs text-muted-foreground">{clientInfo.accountManager.role}</p>
                    <p className="text-xs text-muted-foreground truncate mt-1">{clientInfo.accountManager.email}</p>

                    <div className="flex gap-2 mt-2">
                      <Button size="sm" variant="outline" className="h-7 px-2">
                        <Phone className="h-3 w-3 mr-1" />
                        Call
                      </Button>
                      <Button size="sm" variant="outline" className="h-7 px-2">
                        <Mail className="h-3 w-3 mr-1" />
                        Email
                      </Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <HelpCircle className="h-4 w-4 mr-2" />
                  View FAQ
                </Button>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <MessageSquare className="h-4 w-4 mr-2" />
                  Previous Tickets
                </Button>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <Phone className="h-4 w-4 mr-2" />
                  Schedule Call
                </Button>
              </CardContent>
            </Card>

            {/* Support Hours */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Support Hours</CardTitle>
              </CardHeader>
              <CardContent className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span>Monday - Friday:</span>
                  <span>9 AM - 6 PM EST</span>
                </div>
                <div className="flex justify-between">
                  <span>Saturday:</span>
                  <span>10 AM - 4 PM EST</span>
                </div>
                <div className="flex justify-between">
                  <span>Sunday:</span>
                  <span>Closed</span>
                </div>

                <div className="mt-3 pt-3 border-t">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-2 bg-green-500 rounded-full" />
                    <span className="text-xs text-green-600 font-medium">Currently Online</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Chat Area */}
          <div className="lg:col-span-3">
            <Card className="h-full flex flex-col">
              {/* Chat Header */}
              <CardHeader className="border-b">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-lg">Live Support Chat</CardTitle>
                    <CardDescription>
                      Chat with our support team in real-time
                    </CardDescription>
                  </div>

                  {clientInfo.accountManager.isOnline && (
                    <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                      <div className="h-2 w-2 bg-green-500 rounded-full mr-2" />
                      Support Online
                    </Badge>
                  )}
                </div>
              </CardHeader>

              {/* Error display */}
              {error && (
                <div className="p-4 border-b">
                  <Alert>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                </div>
              )}

              {/* Messages Area */}
              <div className="flex-1 min-h-0">
                {messagesLoading ? (
                  <div className="p-4 space-y-4">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <div key={i} className="flex gap-3">
                        <Skeleton className="h-8 w-8 rounded-full" />
                        <div className="space-y-2 flex-1">
                          <Skeleton className="h-4 w-1/4" />
                          <Skeleton className="h-16 w-3/4" />
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  currentUser && supportChannel && (
                    <MessageList
                      messages={messages[supportChannel.id] || []}
                      typingUsers={typingUsers[supportChannel.id] || []}
                      currentUserId={currentUser.mongo_member_id}
                      onMessageRead={handleMessageRead}
                      channel_members={supportChannel.channel_members || []}
                    />
                  )
                )}
              </div>

              {/* Message Input */}
              {supportChannel && (
                <div className="border-t">
                  <MessageInput
                    channelId={supportChannel.id}
                    onSend={handleSendMessage}
                    disabled={actionLoading}
                    placeholder="Type your message to support..."
                    allowAttachments={true}
                    className="border-0"
                  />
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}