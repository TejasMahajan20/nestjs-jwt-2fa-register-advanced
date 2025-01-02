import * as crypto from 'crypto';
import { Request } from 'express';

export const hashToken = (token: string): string => crypto.createHash('sha256').update(token).digest('hex');

// In seconds
enum TimeUnit {
    SECOND = 1,
    MINUTE = 60,
    HOUR = 60 * 60,
    DAY = 24 * 60 * 60,
    WEEK = 7 * 24 * 60 * 60,
}

export function getJwtExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhdw])$/);
    if (!match) {
        throw new Error("Invalid expiry format.");
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
        case 's':
            return value * TimeUnit.SECOND;
        case 'm':
            return value * TimeUnit.MINUTE;
        case 'h':
            return value * TimeUnit.HOUR;
        case 'd':
            return value * TimeUnit.DAY;
        case 'w':
            return value * TimeUnit.WEEK;
        default:
            throw new Error("Invalid time unit.");
    }
}

export function getIpAddress(req: Request) {
    return req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || req.connection.remoteAddress;
}

export function getUserAgent(req: Request) {
    return req.headers['user-agent'];
}