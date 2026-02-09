import mongoose from 'mongoose'
import dotenv from 'dotenv'

// Load environment variables from .env.local
dotenv.config({ path: '.env.local' })

async function connectToDatabase() {
  const MONGODB_URI = process.env.MONGODB_URI
  if (!MONGODB_URI) {
    throw new Error('Please define the MONGODB_URI environment variable')
  }

  try {
    await mongoose.connect(MONGODB_URI)
    console.log('✅ Connected to MongoDB for reset')
  } catch (error) {
    console.error('❌ MongoDB connection error:', error)
    process.exit(1)
  }
}

async function disconnectFromDatabase() {
  await mongoose.disconnect()
  console.log('✅ Disconnected from MongoDB')
}

async function resetDatabase() {
  try {
    console.log('🚀 Starting database reset...')
    await connectToDatabase()

    // Get all collections
    const db = mongoose.connection.db
    if (!db) {
      throw new Error('Database connection not established')
    }

    const collections = await db.listCollections().toArray()

    if (!collections.length) {
      console.log('No collections found to drop')
      return
    }

    // Drop each collection
    for (const collection of collections) {
      try {
        await db.dropCollection(collection.name)
        console.log(`✅ Dropped collection: ${collection.name}`)
      } catch (error) {
        console.error(`❌ Error dropping collection ${collection.name}:`, error)
      }
    }

    console.log('✨ Database reset completed')
    await disconnectFromDatabase()
  } catch (error) {
    console.error('❌ Error during database reset:', error)
    await disconnectFromDatabase()
    process.exit(1)
  }
}

// Run the reset
resetDatabase()