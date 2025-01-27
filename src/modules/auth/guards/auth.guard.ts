import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AuthMessages } from '../constants/messages.constant';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorator/public.decorator';
import { UserService } from '../services/user.service';
import { AuthService } from '../auth.service';
import { getAuthStrategy } from '../strategies/auth.strategy';
import { RedisService } from 'src/common/services/redis.service';
import { StrategyType } from '../enum/strategy-type.enum';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private jwtService: JwtService,
        private reflector: Reflector,
        private configService: ConfigService,
        private userService: UserService,
        private authService: AuthService,
        private redisService: RedisService,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (isPublic) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        if (!token) {
            throw new UnauthorizedException(AuthMessages.Error.TokenNotFound);
        }

        try {
            const payload = await this.jwtService.verifyAsync(
                token,
                {
                    secret: this.configService.get<string>('JWT_SECRET_KEY')
                }
            );

            // Token blacklisting
            // if (await this.authService.isTokenBlacklisted(token)) {
            //     throw new UnauthorizedException(AuthMessages.Error.RevokedToken);
            // }

            // N-Session-At-A-Time
            if (await this.authService.isInvalidSession(payload.uuid, token)) {
                throw new UnauthorizedException(AuthMessages.Error.InvalidToken);
            }

            // One-session-at-a-time
            // if (!await this.authService.isTokenValid(payload.uuid, token)) {
            //     throw new UnauthorizedException(AuthMessages.Error.InvalidToken);
            // }

            // const strategyType = (process.env.AUTH_STRATEGY || 'blacklisting') as StrategyType;
            // const authStrategy = getAuthStrategy(strategyType, this.redisService);
            // if (!await authStrategy.validateToken(payload.uuid, token)) {
            //     throw new UnauthorizedException(AuthMessages.Error.InvalidToken);
            // }

            // Validate user against database
            const userEntity = await this.userService.validateUserByUuid(payload.uuid);

            request.user = userEntity; // Attach user entity to request as 'user'
            request.tokenDetails = { token, uuid: payload.uuid, exp: payload.exp }; // Attach tokenDetails to request

            return true;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException(AuthMessages.Error.TokenExpired);
            }

            // if error.message = undefined it will not included in error response
            throw new UnauthorizedException(error?.message);
        }
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}