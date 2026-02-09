import mongoose from 'mongoose'

const settingsSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  value: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  description: {
    type: String,
    trim: true
  },
  category: {
    type: String,
    required: true,
    enum: ['appearance', 'security', 'notifications', 'system', 'general'],
    default: 'general'
  },
  isPublic: {
    type: Boolean,
    default: false,
    description: 'Whether this setting can be accessed by non-admin users'
  },
  metadata: {
    createdBy: {
      type: String,
      required: true
    },
    updatedBy: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  }
}, {
  timestamps: true
})

// Indexes for better performance
settingsSchema.index({ category: 1, key: 1 })
settingsSchema.index({ isPublic: 1 })
// settingsSchema.index({ key: 1 }, { unique: true }) // Removed - duplicate of unique: true in field definition

// Update the updatedAt field on save
settingsSchema.pre('save', function (next) {
  (this as ISettings).metadata.updatedAt = new Date()
  next()
})

// Static methods for common operations
settingsSchema.statics.getSetting = async function (key: string) {
  return await this.findOne({ key }).lean()
}

settingsSchema.statics.setSetting = async function (key: string, value: any, category: string = 'general', updatedBy: string = 'system') {
  return await this.findOneAndUpdate(
    { key },
    {
      key,
      value,
      category,
      'metadata.updatedBy': updatedBy,
      'metadata.updatedAt': new Date()
    },
    {
      new: true,
      upsert: true,
      runValidators: true,
      setDefaultsOnInsert: true
    }
  )
}

settingsSchema.statics.getPublicSettings = async function (category?: string) {
  const query: any = { isPublic: true }
  if (category) {
    query.category = category
  }
  return await this.find(query).select('key value description category').lean()
}

settingsSchema.statics.getSettingsByCategory = async function (category: string) {
  return await this.find({ category }).sort({ key: 1 }).lean()
}

// Export types
export interface ISettings extends mongoose.Document {
  key: string
  value: any
  description?: string
  category: 'appearance' | 'security' | 'notifications' | 'system' | 'general'
  isPublic: boolean
  metadata: {
    createdBy: string
    updatedBy: string
    createdAt: Date
    updatedAt: Date
  }
}

export interface ISettingsModel extends mongoose.Model<ISettings> {
  getSetting(key: string): Promise<ISettings | null>
  setSetting(key: string, value: any, category?: string, updatedBy?: string): Promise<ISettings>
  getPublicSettings(category?: string): Promise<ISettings[]>
  getSettingsByCategory(category: string): Promise<ISettings[]>
}

const Settings = (mongoose.models.Settings as ISettingsModel) ||
  mongoose.model<ISettings, ISettingsModel>('Settings', settingsSchema)

export default Settings