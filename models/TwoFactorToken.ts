import mongoose, { Schema, type Document } from "mongoose"

export interface ITwoFactorToken extends Document {
    email: string
    tokenHash: string
    expiresAt: Date
    attempts: number
    createdAt: Date
}

const TwoFactorTokenSchema = new Schema<ITwoFactorToken>(
    {
        email: {
            type: String,
            required: true,
            index: true,
        },
        tokenHash: {
            type: String,
            required: true,
        },
        expiresAt: {
            type: Date,
            required: true,
            index: { expires: 0 }, // TTL index for automatic cleanup
        },
        attempts: {
            type: Number,
            default: 0,
        },
    },
    {
        timestamps: { createdAt: true, updatedAt: false },
    }
)

// Compound index for efficient queries
TwoFactorTokenSchema.index({ email: 1, expiresAt: 1 })

const TwoFactorToken = mongoose.models.TwoFactorToken ||
    mongoose.model<ITwoFactorToken>("TwoFactorToken", TwoFactorTokenSchema)

// Register the model with the generic registry
import { registerModel } from '../lib/modelRegistry'
registerModel('TwoFactorToken', TwoFactorToken, TwoFactorTokenSchema, '1.0.0', [])

export default TwoFactorToken