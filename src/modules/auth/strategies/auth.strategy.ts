import { StrategyType } from "../enum/strategy-type.enum";
import { IAuthStrategy } from "../interfaces/auth-strategy.interface";

// Blacklisting Strategy
export class BlacklistingStrategy implements IAuthStrategy {
    async validateToken(token: string): Promise<boolean> {
        // Check if token is blacklisted
        return true
    }

    async handleSession(userId: string, token: string): Promise<void> {
        // Blacklist old tokens if necessary
    }
}

// One-Session-at-a-Time Strategy
export class OneSessionStrategy implements IAuthStrategy {
    async validateToken(token: string): Promise<boolean> {
        // Check if token matches the single active session for the user
        return true
    }

    async handleSession(userId: string, token: string): Promise<void> {
        // Invalidate previous session for this user
    }
}

// N-Sessions Strategy
export class NSessionsStrategy implements IAuthStrategy {
    async validateToken(token: string): Promise<boolean> {
        // Check if token exists in the list of valid sessions for the user
        return true
    }

    async handleSession(userId: string, token: string): Promise<void> {
        // Add token to session list, evict oldest if limit is exceeded
    }
}

export const getAuthStrategy = (strategyType: StrategyType) => {
    switch (strategyType) {
        case StrategyType.BLACKLISTING:
            return new BlacklistingStrategy();
        case StrategyType.ONE_SESSION:
            return new OneSessionStrategy();
        case StrategyType.N_SESSIONS:
            return new NSessionsStrategy();
        default:
            return new BlacklistingStrategy();
    }
};