import mongoose from 'mongoose'

// Import all models to ensure they're registered with relative paths
import '../../models/User'
import '../../models/Role'
import '../../models/Department'
import '../../models/SystemPermission'

// Global interface for caching connection
declare global {
  var mongoose: {
    conn: typeof import('mongoose') | null
    promise: Promise<typeof import('mongoose')> | null
  }
}

// Use global variable to cache connection across hot reloads
let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null }
}

async function connectDB() {
  // Return existing connection if available
  if (cached.conn) {
    console.log('🔄 Using existing MongoDB connection')
    return cached.conn
  }

  // If no MONGODB_URI is provided, throw error
  if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI environment variable is not defined')
  }

  // If no promise exists, create one
  if (!cached.promise) {
    console.log('🚀 Creating new MongoDB connection...')
    
    // Modern mongoose connection options
    const opts = {
      bufferCommands: false,
      maxPoolSize: 10,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4
    }

    // Create the connection promise
    cached.promise = mongoose.connect(process.env.MONGODB_URI, opts).then((mongoose) => {
      console.log('✅ Successfully connected to MongoDB')
      console.log(`📊 Database: ${mongoose.connection.db?.databaseName}`)
      console.log(`🔗 Host: ${mongoose.connection.host}:${mongoose.connection.port}`)
      return mongoose
    }).catch((error) => {
      console.error('❌ MongoDB connection failed:', error.message)
      cached.promise = null // Reset promise on error
      throw error
    })
  }

  try {
    cached.conn = await cached.promise
  } catch (error) {
    console.error('💥 Failed to establish MongoDB connection:', error)
    cached.promise = null
    cached.conn = null
    throw error
  }

  return cached.conn
}

// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('🟢 MongoDB connection established')
})

mongoose.connection.on('error', (error) => {
  console.error('🔴 MongoDB connection error:', error)
})

mongoose.connection.on('disconnected', () => {
  console.log('🟡 MongoDB connection lost')
})

// Graceful shutdown
process.on('SIGINT', async () => {
  if (cached.conn) {
    await mongoose.connection.close()
    console.log('🔌 MongoDB connection closed through app termination')
    process.exit(0)
  }
})
    
export default connectDB