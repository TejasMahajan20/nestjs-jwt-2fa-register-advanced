export interface IAuthStrategy {
    validateToken(token: string): Promise<boolean>;
    handleSession(userId: string, token: string): Promise<void>;
}