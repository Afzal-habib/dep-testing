import mongoose from 'mongoose'

export interface ModelDefinition {
  name: string
  model: mongoose.Model<any>
  schema: mongoose.Schema
  version: string
  dependencies?: string[]
}

export class ModelRegistry {
  private static instance: ModelRegistry
  private models: Map<string, ModelDefinition> = new Map()

  private constructor() {}

  public static getInstance(): ModelRegistry {
    if (!ModelRegistry.instance) {
      ModelRegistry.instance = new ModelRegistry()
    }
    return ModelRegistry.instance
  }

  /**
   * Manually register a model
   */
  public registerModel(name: string, model: mongoose.Model<any>, schema: mongoose.Schema, version: string = '1.0.0', dependencies?: string[]): void {
    const modelDef: ModelDefinition = {
      name,
      model,
      schema,
      version,
      dependencies
    }

    this.models.set(name, modelDef)
    console.log(`✅ Registered model: ${name} (v${version})`)
  }

  /**
   * Get all registered models
   */
  public getAllModels(): Map<string, ModelDefinition> {
    return this.models
  }

  /**
   * Get a specific model by name
   */
  public getModel(name: string): ModelDefinition | undefined {
    return this.models.get(name)
  }

  /**
   * Get models sorted by dependencies
   */
  public getModelsByDependencyOrder(): ModelDefinition[] {
    const models = Array.from(this.models.values())
    const visited = new Set<string>()
    const result: ModelDefinition[] = []

    const visit = (modelDef: ModelDefinition) => {
      if (visited.has(modelDef.name)) return

      // Visit dependencies first
      if (modelDef.dependencies) {
        for (const dep of modelDef.dependencies) {
          const depModel = this.models.get(dep)
          if (depModel) {
            visit(depModel)
          }
        }
      }

      visited.add(modelDef.name)
      result.push(modelDef)
    }

    // Visit all models
    for (const modelDef of models) {
      visit(modelDef)
    }

    return result
  }

  /**
   * Validate all models are properly registered
   */
  public validateModels(): { valid: boolean; errors: string[] } {
    const errors: string[] = []

    for (const [name, modelDef] of Array.from(this.models)) {
      // Check if model is registered with mongoose
      if (!mongoose.models[name]) {
        errors.push(`Model ${name} is not registered with mongoose`)
      }

      // Check schema validity
      try {
        // Basic schema validation
        if (!modelDef.schema || typeof modelDef.schema !== 'object') {
          errors.push(`Model ${name} has invalid schema`)
        }
      } catch (error) {
        errors.push(`Model ${name} schema validation failed: ${error}`)
      }
    }

    return {
      valid: errors.length === 0,
      errors
    }
  }

  /**
   * Get model statistics
   */
  public getStats(): {
    total: number
    withDependencies: number
    versions: Record<string, number>
  } {
    const stats = {
      total: this.models.size,
      withDependencies: 0,
      versions: {} as Record<string, number>
    }

    for (const modelDef of Array.from(this.models.values())) {
      if (modelDef.dependencies && modelDef.dependencies.length > 0) {
        stats.withDependencies++
      }

      const version = modelDef.version
      stats.versions[version] = (stats.versions[version] || 0) + 1
    }

    return stats
  }
}

// Export singleton instance
export const modelRegistry = ModelRegistry.getInstance()

// Convenience functions
export async function registerAllModels(): Promise<void> {
  // Models are now registered manually when imported
  console.log('📋 Models registered via manual registration')
}

export function validateAllModels(): { valid: boolean; errors: string[] } {
  console.log('🔍 Validating models...')
  const result = modelRegistry.validateModels()
  console.log(`📊 Found ${modelRegistry.getAllModels().size} registered models`)
  return result
}

// Helper function for models to register themselves
export function registerModel(name: string, model: mongoose.Model<any>, schema: mongoose.Schema, version: string = '1.0.0', dependencies?: string[]): void {
  modelRegistry.registerModel(name, model, schema, version, dependencies)
}