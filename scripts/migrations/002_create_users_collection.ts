import mongoose from 'mongoose'

const userSchema = {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['name', 'email', 'password', 'role'],
      properties: {
        name: {
          bsonType: 'string',
          description: 'must be a string and is required'
        },
        email: {
          bsonType: 'string',
          pattern: '^\\w+([.-]?\\w+)*@\\w+([.-]?\\w+)*(\\.\\w{2,3})+$',
          description: 'must be a valid email and is required'
        },
        password: {
          bsonType: 'string',
          minLength: 6,
          description: 'must be a string of at least 6 characters and is required'
        },
        role: {
          enum: ['admin', 'manager', 'user'],
          description: 'must be either admin, manager, or user and is required'
        },
        avatar: {
          bsonType: 'string',
          description: 'must be a string if present'
        },
        phone: {
          bsonType: 'string',
          description: 'must be a string if present'
        },
        department: {
          bsonType: 'string',
          description: 'must be a string if present'
        },
        status: {
          bsonType: 'string',
          enum: ['active', 'inactive', 'archived'],
          description: 'must be either active, inactive, or archived'
        }
      }
    }
  }
}

export async function up(): Promise<void> {
  try {
    const db = mongoose.connection.db
    if (!db) {
      throw new Error('Database connection not established')
    }

    // Check if collection exists
    const collections = await db.listCollections().toArray()
    const collectionExists = collections.some(col => col.name === 'users')

    if (collectionExists) {
      console.log('✅ Users collection already exists, updating schema validation...')
      await db.command({
        collMod: 'users',
        ...userSchema
      })
    } else {
      // Create the users collection with schema validation
      await mongoose.connection.createCollection('users', userSchema)
    }

    // Create or update indexes
    const users = mongoose.connection.collection('users')
    await users.createIndex({ email: 1 }, { unique: true })
    await users.createIndex({ role: 1 })
    await users.createIndex({ department: 1 })
    await users.createIndex({ status: 1 })

    console.log('✅ Users collection schema and indexes updated')
  } catch (error) {
    console.error('❌ Error in migration:', error)
    throw error
  }
}

export async function down(): Promise<void> {
  try {
    const db = mongoose.connection.db
    if (!db) {
      throw new Error('Database connection not established')
    }

    await db.dropCollection('users')
    console.log('✅ Users collection dropped')
  } catch (error) {
    console.error('❌ Error in migration rollback:', error)
    throw error
  }
}