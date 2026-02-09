// Rate limiter utility for server-side only
import { NextRequest, NextResponse } from "next/server"

let RateLimiterMemory: any = null;

// Dynamically import rate-limiter-flexible only on server
const getRateLimiterMemory = async () => {
  if (!RateLimiterMemory) {
    const { RateLimiterMemory: RLM } = await import("rate-limiter-flexible");
    RateLimiterMemory = RLM;
  }
  return RateLimiterMemory;
};

// Initialize rate limiters lazily
export let rateLimiters: any = null;

const initializeRateLimiters = async () => {
  if (rateLimiters) return rateLimiters;

  const RLM = await getRateLimiterMemory();

  rateLimiters = {
    auth: new RLM({
      points: 5, // Number of attempts
      duration: 900, // Per 15 minutes (in seconds)
      blockDuration: 900, // Block for 15 minutes
    }),

    api: new RLM({
      // points: 100, // Number of requests
      points: 300, // Number of requests
      duration: 900, // Per 15 minutes (in seconds)
      blockDuration: 300, // Block for 5 minutes (lighter for API)
    }),

    sensitive: new RLM({
      // points: 10, // Number of requests  
      points: 100, // Number of requests  
      duration: 900, // Per 15 minutes (in seconds)
      blockDuration: 900, // Block for 15 minutes
    }),
  };

  return rateLimiters;
};

export async function applyRateLimit(
  request: NextRequest | any,
  type: "auth" | "api" | "sensitive" = "api"
): Promise<NextResponse | null> {
  try {
    const limiters = await initializeRateLimiters();
    
    // Handle different request types (NextRequest vs mock request)
    let ip: string;
    if (request.headers && typeof request.headers.get === 'function') {
      // NextRequest object
      ip = request.headers.get("x-forwarded-for") ||
        request.headers.get("x-real-ip") ||
        "anonymous"
    } else if (request.ip) {
      // Mock request object with ip property
      ip = request.ip
    } else if (request.headers && request.headers['x-forwarded-for']) {
      // Mock request with headers object
      ip = request.headers['x-forwarded-for']
    } else {
      ip = "anonymous"
    }
    
    const rateLimiter = limiters[type]

    await rateLimiter.consume(ip)
    return null // No rate limit exceeded
  } catch (rejRes: any) {
    const secs = Math.round(rejRes.msBeforeNext / 1000) || 1
    const limiters = await initializeRateLimiters();
    const currentRateLimiter = limiters[type]

    return NextResponse.json(
      {
        success: false,
        message: "Too many requests",
        error: `Rate limit exceeded. Try again in ${secs} seconds.`,
        retryAfter: secs,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(secs),
          "X-RateLimit-Limit": String(currentRateLimiter.points),
          "X-RateLimit-Remaining": String(rejRes.remainingPoints || 0),
          "X-RateLimit-Reset": String(new Date(Date.now() + rejRes.msBeforeNext)),
        },
      }
    )
  }
}

export function getRateLimitHeaders(remainingPoints: number, totalPoints: number, resetTime: Date) {
  return {
    "X-RateLimit-Limit": String(totalPoints),
    "X-RateLimit-Remaining": String(remainingPoints),
    "X-RateLimit-Reset": resetTime.toISOString(),
  }
}
