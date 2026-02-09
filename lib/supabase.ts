import { createClient, SupabaseClient } from '@supabase/supabase-js'
import type { Database } from '@/types/supabase'

// Supabase configuration
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

const globalForSupabase = globalThis as unknown as {
  supabase: SupabaseClient<Database> | undefined
}

// Create Supabase client with singleton pattern
export const supabase =
  globalForSupabase.supabase ??
  createClient<Database>(supabaseUrl, supabaseAnonKey, {
    // auth: {
    //   autoRefreshToken: true,
    //   persistSession: true,
    //   detectSessionInUrl: true
    // },
    realtime: {
      params: {
        eventsPerSecond: 10
      }
    }
  })

if (process.env.NODE_ENV !== 'production') globalForSupabase.supabase = supabase

// Default export for convenience
export default supabase

// Database types (will be generated from Supabase)
export type { Database } from '@/types/supabase'