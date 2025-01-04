import { RedisService } from "src/common/services/redis.service";
import { StrategyType } from "../enum/strategy-type.enum";
import { IAuthStrategy } from "../interfaces/auth-strategy.interface";
import { Injectable } from "@nestjs/common";
import { getJwtExpiry, hashToken } from "../utils/helpers.util";
import { RedisPrefix } from "src/common/enum/redis-prefix.enum";
import { BLACKLISTED } from "../constants/variables.constant";
import { IDeviceInfo } from "../interfaces/device-info.interface";

// Blacklisting Strategy
@Injectable()
export class BlacklistingStrategy implements IAuthStrategy {
    constructor(private readonly redisService: RedisService) { }

    async validateToken(userId: string, token: string): Promise<boolean> {
        const hashedToken = hashToken(token);
        const result = await this.redisService.get(
            RedisPrefix.BLACKLISTED_TOKEN,
            hashedToken
        );
        return result === BLACKLISTED;
    }

    async handleSession(token: string, ttl: number): Promise<void> {
        const hashedToken = hashToken(token);
        await this.redisService.setWithExpiry(
            RedisPrefix.BLACKLISTED_TOKEN,
            hashedToken,
            BLACKLISTED,
            ttl
        );
    }
}

// One-Session-at-a-Time Strategy
@Injectable()
export class OneSessionStrategy implements IAuthStrategy {
    constructor(private readonly redisService: RedisService) { }

    async validateToken(userId: string, token: string): Promise<boolean> {
        const hashedToken = hashToken(token);
        const sessionToken = await this.redisService.get(
            RedisPrefix.SESSION,
            userId
        );
        return hashedToken === sessionToken;
    }

    async handleSession(userId: string, token: string): Promise<void> {
        const hashedToken = hashToken(token);
        const ttl = getJwtExpiry(process.env.JWT_EXPIRATION_TIME ?? '1d');
        await this.redisService.setWithExpiry(
            RedisPrefix.SESSION,
            userId,
            hashedToken,
            ttl
        );
    }
}

// N-Sessions Strategy
@Injectable()
export class NSessionsStrategy implements IAuthStrategy {
    constructor(private readonly redisService: RedisService) { }

    async validateToken(userId: string, token: string): Promise<boolean> {
        const hashedToken = hashToken(token);
        const key = `${RedisPrefix.SESSION}:${userId}`;
        const sessionExists = await this.redisService.redisClient.hget(
            key,
            hashedToken
        );
        return sessionExists === null;
    }

    async handleSession(userId: string, token: string, deviceInfo: IDeviceInfo): Promise<void> {
        const hashedToken = hashToken(token);
        const key = `${RedisPrefix.SESSION}:${userId}`;
        const sessionMeta = JSON.stringify(deviceInfo);
        await this.redisService.redisClient.hset(key, hashedToken, sessionMeta);
    }
}

export const getAuthStrategy = (strategyType: StrategyType, redisService: RedisService) => {
    switch (strategyType) {
        case StrategyType.BLACKLISTING:
            return new BlacklistingStrategy(redisService);
        case StrategyType.ONE_SESSION:
            return new OneSessionStrategy(redisService);
        case StrategyType.N_SESSIONS:
            return new NSessionsStrategy(redisService);
        default:
            return new BlacklistingStrategy(redisService);
    }
};