import crypto from 'crypto'

// Use a strong app secret (store in .env.local)
const OTP_SECRET_BASE = process.env.OTP_SECRET_BASE || 'your-super-secret-64-char-hex-string-replace-in-production'

/**
 * Generate a 6-digit OTP for email-based 2FA using time-based approach
 * @param email - User's email address (used as salt)
 * @returns Object containing token, tokenHash, and timestamp
 */
export const generateOTP = (email: string) => {
    // Create user-specific secret using email as salt
    const secret = crypto
        .createHmac('sha256', OTP_SECRET_BASE)
        .update(email.toLowerCase())
        .digest('hex')

    // Get current time window (2 minutes = 120 seconds)
    const timeWindow = Math.floor(Date.now() / (120 * 1000))

    // Generate token based on time window and secret
    const token = crypto
        .createHmac('sha256', secret)
        .update(timeWindow.toString())
        .digest('hex')
        .slice(0, 6) // Take first 6 characters
        .replace(/[a-f]/g, (match) => (parseInt(match, 16) % 10).toString()) // Convert hex to digits

    // Ensure it's exactly 6 digits
    const sixDigitToken = (parseInt(token, 16) % 900000 + 100000).toString()

    // Hash the token for secure storage
    const tokenHash = crypto
        .createHash('sha256')
        .update(sixDigitToken)
        .digest('hex')

    return { token: sixDigitToken, tokenHash, secret }
}

/**
 * Verify a 6-digit OTP
 * @param token - The OTP token to verify
 * @param email - User's email address (used as salt)
 * @param allowPreviousWindow - Allow previous time window (default: true)
 * @returns Boolean indicating if token is valid
 */
export const verifyOTP = (token: string, email: string, allowPreviousWindow: boolean = true): boolean => {
    try {
        // Create user-specific secret using email as salt
        const secret = crypto
            .createHmac('sha256', OTP_SECRET_BASE)
            .update(email.toLowerCase())
            .digest('hex')

        // Get current time window
        const currentTimeWindow = Math.floor(Date.now() / (120 * 1000))

        // Check current window
        const currentToken = generateTokenForWindow(secret, currentTimeWindow)
        if (currentToken === token) {
            return true
        }

        // Check previous window if allowed (for slight time drift)
        if (allowPreviousWindow) {
            const previousToken = generateTokenForWindow(secret, currentTimeWindow - 1)
            if (previousToken === token) {
                return true
            }
        }

        return false
    } catch (error) {
        console.error('OTP verification error:', error)
        return false
    }
}

/**
 * Generate token for a specific time window
 * @param secret - The secret key
 * @param timeWindow - The time window
 * @returns Generated token
 */
const generateTokenForWindow = (secret: string, timeWindow: number): string => {
    const token = crypto
        .createHmac('sha256', secret)
        .update(timeWindow.toString())
        .digest('hex')
        .slice(0, 6)
        .replace(/[a-f]/g, (match) => (parseInt(match, 16) % 10).toString())

    return (parseInt(token, 16) % 900000 + 100000).toString()
}

/**
 * Hash a token for secure storage
 * @param token - The token to hash
 * @returns Hashed token
 */
export const hashToken = (token: string): string => {
    return crypto
        .createHash('sha256')
        .update(token)
        .digest('hex')
}

/**
 * Generate a magic link token (longer, more secure)
 * @param email - User's email address
 * @returns Object containing token and its hash
 */
export const generateMagicLinkToken = (email: string) => {
    // Generate a random token for magic links
    const randomBytes = crypto.randomBytes(32)
    const timestamp = Date.now().toString()
    const emailHash = crypto
        .createHash('sha256')
        .update(email.toLowerCase())
        .digest('hex')

    // Combine and hash for unique token
    const token = crypto
        .createHash('sha256')
        .update(randomBytes.toString('hex') + timestamp + emailHash)
        .digest('hex')

    const tokenHash = hashToken(token)

    return { token, tokenHash }
}

/**
 * Check if a timestamp is within the 2-minute window
 * @param timestamp - The timestamp to check
 * @returns Boolean indicating if timestamp is still valid
 */
export const isWithinTimeWindow = (timestamp: Date): boolean => {
    const now = new Date()
    const diffInMs = now.getTime() - timestamp.getTime()
    const diffInMinutes = diffInMs / (1000 * 60)

    return diffInMinutes <= 2 // 2 minutes window
}

/**
 * Generate a secure random 6-digit code (alternative to TOTP)
 * @returns Object containing code and its hash
 */
export const generateSecureCode = () => {
    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString()
    const codeHash = hashToken(code)

    return { code, codeHash }
}

/**
 * Verify if the provided code matches the stored hash
 * @param code - The code to verify
 * @param storedHash - The stored hash to verify against
 * @returns Boolean indicating if code is valid
 */
export const verifyCode = (code: string, storedHash: string): boolean => {
    const codeHash = hashToken(code)
    return codeHash === storedHash
}