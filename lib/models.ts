// Generic Model Registry - Import and register all models
import { registerAllModels, modelRegistry } from './modelRegistry'

// Import all models (this registers them automatically)
import '../models/User'
import '../models/Role'
import '../models/Department'
import '../models/Project'
import '../models/Task'
import '../models/SystemPermission'
import '../models/Media'
import '../models/Settings'
import '../models/Lead'
// import '../models/Phase'
// import '../models/Milestone'
// import '../models/MilestoneTemplate'
// import '../models/MilestoneApproval'
import '../models/Comment'
import '../models/Media'
import '../models/TimeLog'
import '../models/TwoFactorToken'

// Initialize model registration
let modelsRegistered = false

export const registerModels = async () => {
  if (modelsRegistered) {
    console.log('📋 Models already registered')
    return
  }

  try {
    await registerAllModels()
    modelsRegistered = true
    console.log('✅ All models registered successfully')
  } catch (error) {
    console.error('❌ Error registering models:', error)
    throw error
  }
}

// Export individual models for backward compatibility
export const getModel = (name: string) => {
  const modelDef = modelRegistry.getModel(name)
  return modelDef ? modelDef.model : null
}

// Export all models as an object
export const getAllModels = () => {
  const models: Record<string, any> = {}
  for (const [name, modelDef] of Array.from(modelRegistry.getAllModels())) {
    models[name] = modelDef.model
  }
  return models
}

// Legacy exports for backward compatibility
export { modelRegistry }