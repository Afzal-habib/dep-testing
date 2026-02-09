export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export interface Database {
  public: {
    Tables: {
      channels: {
        Row: {
          id: string
          type: string
          name: string | null
          avatar_url: string | null
          mongo_department_id: string | null
          mongo_project_id: string | null
          mongo_creator_id: string
          is_private: boolean
          member_count: number
          last_message_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          type: string
          name?: string | null
          avatar_url?: string | null
          mongo_department_id?: string | null
          mongo_project_id?: string | null
          mongo_creator_id: string
          is_private?: boolean
          member_count?: number
          last_message_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          type?: string
          name?: string | null
          avatar_url?: string | null
          mongo_department_id?: string | null
          mongo_project_id?: string | null
          mongo_creator_id?: string
          is_private?: boolean
          member_count?: number
          last_message_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: []
      }
      messages: {
        Row: {
          id: string
          channel_id: string
          mongo_sender_id: string
          content: string
          content_type: string
          thread_id: string | null
          reply_count: number
          mongo_mentioned_user_ids: string[]
          is_edited: boolean
          edited_at: string | null
          created_at: string
        }
        Insert: {
          id?: string
          channel_id: string
          mongo_sender_id: string
          content: string
          content_type?: string
          thread_id?: string | null
          reply_count?: number
          mongo_mentioned_user_ids?: string[]
          is_edited?: boolean
          edited_at?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          channel_id?: string
          mongo_sender_id?: string
          content?: string
          content_type?: string
          thread_id?: string | null
          reply_count?: number
          mongo_mentioned_user_ids?: string[]
          is_edited?: boolean
          edited_at?: string | null
          created_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "messages_channel_id_fkey"
            columns: ["channel_id"]
            isOneToOne: false
            referencedRelation: "channels"
            referencedColumns: ["id"]
          }
        ]
      }
      channel_members: {
        Row: {
          id: string
          channel_id: string
          mongo_member_id: string
          role: string
          joined_at: string
          last_seen_at: string | null
          is_online: boolean
          notifications_enabled: boolean
        }
        Insert: {
          id?: string
          channel_id: string
          mongo_member_id: string
          role?: string
          joined_at?: string
          last_seen_at?: string | null
          is_online?: boolean
          notifications_enabled?: boolean
        }
        Update: {
          id?: string
          channel_id?: string
          mongo_member_id?: string
          role?: string
          joined_at?: string
          last_seen_at?: string | null
          is_online?: boolean
          notifications_enabled?: boolean
        }
        Relationships: [
          {
            foreignKeyName: "channel_members_channel_id_fkey"
            columns: ["channel_id"]
            isOneToOne: false
            referencedRelation: "channels"
            referencedColumns: ["id"]
          }
        ]
      }
      read_receipts: {
        Row: {
          id: string
          message_id: string
          mongo_user_id: string
          read_at: string
        }
        Insert: {
          id?: string
          message_id: string
          mongo_user_id: string
          read_at?: string
        }
        Update: {
          id?: string
          message_id?: string
          mongo_user_id?: string
          read_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "read_receipts_message_id_fkey"
            columns: ["message_id"]
            isOneToOne: false
            referencedRelation: "messages"
            referencedColumns: ["id"]
          }
        ]
      }
      reactions: {
        Row: {
          id: string
          message_id: string
          channel_id: string
          mongo_user_id: string
          emoji: string
          created_at: string
        }
        Insert: {
          id?: string
          message_id: string
          channel_id: string
          mongo_user_id: string
          emoji: string
          created_at?: string
        }
        Update: {
          id?: string
          message_id?: string
          channel_id?: string
          mongo_user_id?: string
          emoji?: string
          created_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "reactions_channel_id_fkey"
            columns: ["channel_id"]
            isOneToOne: false
            referencedRelation: "channels"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "reactions_message_id_fkey"
            columns: ["message_id"]
            isOneToOne: false
            referencedRelation: "messages"
            referencedColumns: ["id"]
          }
        ]
      }
      attachments: {
        Row: {
          id: string
          message_id: string
          channel_id: string
          mongo_uploader_id: string
          file_name: string
          file_url: string | null
          s3_key: string | null
          s3_bucket: string | null
          file_size: number | null
          file_type: string | null
          created_at: string
        }
        Insert: {
          id?: string
          message_id: string
          channel_id: string
          mongo_uploader_id: string
          file_name: string
          file_url?: string | null
          s3_key?: string | null
          s3_bucket?: string | null
          file_size?: number | null
          file_type?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          message_id?: string
          channel_id?: string
          mongo_uploader_id?: string
          file_name?: string
          file_url?: string | null
          s3_key?: string | null
          s3_bucket?: string | null
          file_size?: number | null
          file_type?: string | null
          created_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "attachments_channel_id_fkey"
            columns: ["channel_id"]
            isOneToOne: false
            referencedRelation: "channels"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "attachments_message_id_fkey"
            columns: ["message_id"]
            isOneToOne: false
            referencedRelation: "messages"
            referencedColumns: ["id"]
          }
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}