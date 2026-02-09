import mongoose from 'mongoose'

// Import all models to ensure they're registered
// Note: Models are now auto-registered via modelRegistry
// import '@/models/User'
// import '@/models/Role'
// import '@/models/Department'
// import '@/models/SystemPermission'
// import '@/models/Communication'
// import '@/models/Channel'

// Connection caching for Next.js environment
let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null }
}

// Simple cache for query results
const queryCache = new Map<string, { data: any; timestamp: number; ttl: number }>()

/**
 * MongoDB connection with singleton pattern
 * Ensures only one connection per application lifecycle
 */
async function connectDB(): Promise<{ db: mongoose.Connection['db'] }> {
  // Return existing connection if available
  if (cached.conn) {
    return { db: cached.conn.connection.db }
  }

  // Validate environment variable
  if (!process.env.MONGODB_URI) {
    throw new Error('❌ MONGODB_URI environment variable is not defined')
  }

  // If no promise exists, create one
  if (!cached.promise) {
    console.log('🚀 Connecting to MongoDB...')

    const opts = {
      maxPoolSize: 10,
      minPoolSize: 2,
      maxIdleTimeMS: 30000,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    }

    cached.promise = mongoose.connect(process.env.MONGODB_URI, opts).then((mongoose) => {
      console.log('✅ MongoDB connected successfully')
      console.log(`📊 Database: ${mongoose.connection.db?.databaseName}`)
      return mongoose
    }).catch((error) => {
      console.error('❌ MongoDB connection failed:', error.message)
      cached.promise = null // Reset on error
      throw error
    })
  }

  try {
    cached.conn = await cached.promise
  } catch (error) {
    console.error('💥 Connection error:', error)
    cached.promise = null
    cached.conn = null
    throw error
  }

  return { db: cached.conn.connection.db }
}

/**
 * Enhanced query function with optional caching
 */
async function executeGenericDbQuery<T>(
  queryFn: () => Promise<T>, 
  cacheKey?: string, 
  cacheTtl: number = 30000
): Promise<T> {
  // Check cache first
  if (cacheKey && queryCache.has(cacheKey)) {
    const cached = queryCache.get(cacheKey)!
    if (Date.now() - cached.timestamp < cached.ttl) {
      return cached.data
    }
    queryCache.delete(cacheKey)
  }

  // Ensure connection
  await connectDB()

  // Execute query
  const result = await queryFn()

  // Cache result
  if (cacheKey) {
    queryCache.set(cacheKey, {
      data: result,
      timestamp: Date.now(),
      ttl: cacheTtl
    })
  }

  return result
}

/**
 * Clear cache by pattern
 */
function clearCache(pattern?: string): void {
  if (!pattern) {
    queryCache.clear()
    return
  }

  for (const key of Array.from(queryCache.keys())) {
    if (key.includes(pattern)) {
      queryCache.delete(key)
    }
  }
}

// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('🟢 MongoDB ready')
})

mongoose.connection.on('error', (error) => {
  console.error('🔴 MongoDB error:', error.message)
})

mongoose.connection.on('disconnected', () => {
  console.log('🟡 MongoDB disconnected')
  cached.conn = null
  cached.promise = null
})

// Graceful shutdown
process.on('SIGINT', async () => {
  if (cached.conn) {
    await mongoose.connection.close()
    console.log('🔌 MongoDB connection closed')
    process.exit(0)
  }
})

// Global type for Next.js caching
declare global {
  var mongoose: {
    conn: typeof import('mongoose') | null
    promise: Promise<typeof import('mongoose')> | null
  }
}

export default connectDB
export { executeGenericDbQuery, clearCache }