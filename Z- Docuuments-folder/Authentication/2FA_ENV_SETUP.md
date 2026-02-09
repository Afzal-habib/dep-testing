# Two-Factor Authentication Environment Variables
# Add these to your existing .env.local file

# 2FA Configuration
OTP_SECRET_BASE=your-super-secret-64-char-hex-string-replace-in-production-with-crypto-random-bytes

# Email Configuration (if not already set)
FROM_EMAIL=no-reply@yourdomain.com

# AWS SES Configuration (if not already set)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key-id
AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key

# Base URL for magic links
NEXT_PUBLIC_BASE_URL=http://localhost:3000

# Generate a secure OTP_SECRET_BASE using Node.js:
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"