export interface IAuthStrategy {
    validateToken(userId: string, token: string): Promise<boolean>;
    handleSession(...args: any): Promise<any>;
}