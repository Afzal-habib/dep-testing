import { NextRequest, NextResponse } from "next/server";
import otplib, { authenticator } from 'otplib';


(authenticator as any).options = {
    step: 10, // Token valid for 5 minutes
    window: 1, // Allow 1 step before and after
    digits: 6, // 6-digit tokens
    algorithm: 'sha1' // Default algorithm
};


const secret = "your-very-secure-secret"; // Replace
// In production, store this securely and do not hardcode it


export async function GET(request: NextRequest) {
    try {
        // const secret = otplib.authenticator.generateSecret();
        const token = otplib.authenticator.generate(secret);
        return NextResponse.json({ 'token': token, status: 200 });
    }
    catch (error: any) {
        console.error('Error in GET /api/otp:', error);
        return NextResponse.json({ 'error': 'Internal server error' }, { status: 500 });
    }

}



export async function POST(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);
        const token = searchParams.get('token') || '';

        const isValid = otplib.authenticator.check(token, secret);
        if (!isValid) {
            return NextResponse.json({ 'error': 'Invalid OTP token' }, { status: 400 });
        }
        // OTP is valid, proceed with your logic (e.g., authenticate user)
        // For demonstration, we'll just return a success message
        return NextResponse.json({ 'message': 'OTP is valid', status: 200 }, { status: 200 });
    }
    catch (error: any) {
        console.error('Error in POST /api/otp:', error);
        return NextResponse.json({ 'error': 'Internal server error' }, { status: 500 });
    }
}


