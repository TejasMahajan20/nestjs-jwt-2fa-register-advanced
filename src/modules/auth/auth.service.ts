import { BadRequestException, ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { HttpResponseDto } from 'src/common/dto/http-response.dto';
import { AuthMessages, OtpMessages, UserMessages } from './constants/messages.constant';
import { Role } from './enum/role.enum';
import { PasswordService } from './services/password.service';
import { UserService } from './services/user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { SignInUserDto } from './dto/sign-in-user.dto';
import { BaseEmailDto } from './dto/base-email.dto';
import { UserEntity } from './entities/user.entity';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { MailService } from '../mail/mail.service';
import { OtpService } from './services/otp.service';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { RedisService } from 'src/common/services/redis.service';
import { RedisPrefix } from 'src/common/enum/redis-prefix.enum';
import { BLACKLISTED } from './constants/variables.constant';
import { getJwtExpiry, hashToken } from './utils/helpers.util';
import { IDeviceInfo } from './interfaces/device-info.interface';
import { RedisExpiry } from 'src/common/enum/redis-expiry.enum';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private readonly maxSessions = parseInt(process.env.MAX_SESSIONS || '3', 10);
    private readonly maxPasswordAttempts = parseInt(process.env.MAX_PASSWORD_ATTEMPTS || '3', 10);
    private readonly maxResetAttempts = parseInt(process.env.MAX_RESET_ATTEMPTS || '3', 10);
    private readonly maxResendOtpAttempts = parseInt(process.env.MAX_OTP_ATTEMPTS || '3', 10);

    constructor(
        private readonly jwtService: JwtService,
        private readonly userService: UserService,
        private readonly otpService: OtpService,
        private readonly passwordService: PasswordService,
        private readonly mailService: MailService,
        private readonly redisService: RedisService,
    ) {
    }

    async register(createUserDto: CreateUserDto): Promise<HttpResponseDto<string>> {
        const userEntity = await this.userService.findOne({ email: createUserDto.email }, ['otp']);

        if (userEntity && userEntity.isEmailVerified) throw new BadRequestException(UserMessages.Error.IsExist);

        // Ecrypt password
        const hashedPassword = await this.passwordService.hashPassword(createUserDto.password);

        // Continue incomplete registration
        if (userEntity && !userEntity.isEmailVerified) {
            await this.userService.update({ uuid: userEntity.uuid }, { password: hashedPassword });

            await this.upsertOtp(userEntity);

            return new HttpResponseDto(
                OtpMessages.Success.EmailVerificationSent
            );
        }

        // Replace string password with hashed password
        createUserDto.password = hashedPassword;
        createUserDto.role = Role.ADMIN;

        const createdUser = await this.userService.create(createUserDto);
        await this.upsertOtp(createdUser);

        return new HttpResponseDto(
            AuthMessages.Success.RegistrationSuccessful
        );
    }

    async login(signInUserDto: SignInUserDto) {
        // Validate user already exist or not?
        const userEntity = await this.userService.validateUserByEmail(signInUserDto.email);

        this.isEmailVerified(userEntity?.isEmailVerified);

        // Validate password attempts
        await this.validatePasswordAttempts(userEntity.uuid);

        // Remove all logged-in session checkbox was ticked
        // Step to Implement N-Session-at-a-Time
        if (signInUserDto['removeAllSessions']) {
            await this.removeAllSession(userEntity.uuid);
        } else {
            const activeSessions = await this.getSessionCount(userEntity.uuid);
            if (activeSessions >= this.maxSessions) {
                throw new BadRequestException('Maximum sessions reached. Please log out from another session to continue.');
            }
        }

        // Validate user password with stored hashed password
        const isMatch = await this.passwordService.comparePasswords(signInUserDto.password, userEntity.password);
        if (!isMatch) {
            await this.handlePasswordAttempts(userEntity.uuid);
            throw new BadRequestException(UserMessages.Error.IncorrectPassword);
        }

        // Mark 'isForget' to false, because user has recalled his password after forget password request
        if (userEntity?.isForgot) {
            await this.userService.update({ uuid: userEntity.uuid }, { isForgot: false });
        }

        await this.upsertOtp(userEntity);

        return new HttpResponseDto(OtpMessages.Success.OtpSent);
    }

    // For many sessions at a time
    async logout(token: string, ttl: number) {
        if (ttl > 0) {
            await this.blacklistToken(token, ttl);
        }
        return new HttpResponseDto(AuthMessages.Success.LogoutSuccessful);
    }

    // For one sessions at a time
    async logout_(userId: string) {
        await this.deleteSession(userId);
        return new HttpResponseDto(AuthMessages.Success.LogoutSuccessful);
    }

    async forgotPassword(forgotPasswordDto: BaseEmailDto) {
        // Validate user already exist or not?
        const userEntity = await this.userService.validateUserByEmail(forgotPasswordDto.email);

        this.isEmailVerified(userEntity?.isEmailVerified);

        await this.canResetPassword(userEntity.uuid);

        // Mark 'isForget' to true, to allow user to set password instead of jwt token
        await this.userService.update({ uuid: userEntity.uuid }, { isForgot: true });

        await this.upsertOtp(userEntity);

        return new HttpResponseDto(OtpMessages.Success.OtpSent);
    }

    async resetPassword(resetPasswordDto: ResetPasswordDto) {
        // Validate user already exist or not?
        const userEntity = await this.userService.validateUserByEmail(resetPasswordDto.email);

        // Allow only user, who has verified the forget otp?
        if (!userEntity?.otp?.isVerified) {
            throw new BadRequestException(OtpMessages.Error.NotVerified)
        };

        // Validate user password with stored hashed password
        const isMatch = await this.passwordService.comparePasswords(resetPasswordDto.newPassword, userEntity.password);
        if (!isMatch) {
            throw new BadRequestException(UserMessages.Error.PasswordConflict);
        }

        // Hashed password before storing into database
        const hashPassword = await this.passwordService.hashPassword(resetPasswordDto.newPassword);

        await this.userService.update(
            { uuid: userEntity.uuid },
            {
                password: hashPassword,
                isLoggedBefore: true
            }
        );

        await this.redisService.delete(RedisPrefix.INCORRECT_PASSWORD_ATTEMPTS, userEntity.uuid);
        await this.redisService.delete(RedisPrefix.RESET_PASSWORD_ATTEMPTS, userEntity.uuid);

        return new HttpResponseDto(UserMessages.Success.PasswordUpdated);
    }

    async updatePassword(reqUserId: string, updatePasswordDto: UpdatePasswordDto) {
        // Validate user already exist or not?
        const userEntity = await this.userService.validateUserByUuid(reqUserId);

        // Validate user's old password
        if (!await this.passwordService.comparePasswords(updatePasswordDto.oldPassword, userEntity.password)) {
            throw new BadRequestException(UserMessages.Error.IncorrectOldPassword);
        }

        // Hashed password before storing into database
        const hashPassword = await this.passwordService.hashPassword(updatePasswordDto.newPassword);

        await this.userService.update(
            { uuid: userEntity.uuid },
            {
                password: hashPassword,
                isLoggedBefore: true
            }
        );

        return new HttpResponseDto(UserMessages.Success.PasswordUpdated);
    }

    // UPSERT = UPDATE or INSERT
    async upsertOtp(user: UserEntity) {
        // Generate otp and hash it
        const otp = this.otpService.generateNumericOTP();
        console.log(otp);
        const hashedOtp = await this.passwordService.hashPassword(otp);

        // Retrieve otp entity using user and otp relationship
        let otpEntity = user?.otp;

        if (otpEntity) {
            /*
            * If the OTP record exists, update the otp, isVerified to false 
            * and modifiedAt in order to check first-time login or not (it will auto-update due to typeorm superpower)
            */
            await this.otpService.update(
                { uuid: otpEntity.uuid },
                {
                    otp: hashedOtp,
                    isVerified: false
                }
            );
        } else {
            await this.otpService.create({
                user,
                otp: hashedOtp
            });
        }

        // Send mail with queue
        await this.mailService.sendEmail(user.email, otp);

        // Send mail without queue
        // try {
        //     await this.mailService.sendTestEmail(user.email, otp);
        // } catch (error) {
        //     this.logger.error(`Error sending otp to : ${user.email}`);
        // }

        return otp;
    }

    async resendOtp(resendOtpDto: BaseEmailDto) {
        // Validate user already exist or not?
        const userEntity = await this.userService.validateUserByEmail(resendOtpDto.email);

        // Check already verified or not
        if (userEntity?.otp?.isVerified) {
            throw new BadRequestException(OtpMessages.Error.AlreadyVerified);
        }

        // if (user?.otp?.modifiedAt && !this.otpService.isMoreThanTwoMinutes(user?.otp?.modifiedAt)) {
        //     throw new ForbiddenException('Please wait 2 minutes before requesting a new OTP.');
        // }

        // Wait for 2 minutes to get next otp
        if (userEntity?.otp?.modifiedAt) {
            const timeRemaining = this.otpService.getTimeRemaining(userEntity?.otp?.modifiedAt);

            if (timeRemaining > 0) {
                throw new ForbiddenException(`Please wait ${timeRemaining} seconds before requesting a new OTP.`);
            }
        }

        await this.canResendOtp(userEntity.uuid);

        await this.upsertOtp(userEntity);

        return new HttpResponseDto(OtpMessages.Success.OtpSent);
    }

    async verifyOtp(verifyOtpDto: VerifyOtpDto, deviceInfo: IDeviceInfo) {
        // Validate user already exist or not?
        const userEntity = await this.userService.validateUserByEmail(verifyOtpDto.email);

        // Check otp expiry
        if (this.otpService.isExpired(userEntity?.otp?.modifiedAt)) {
            throw new BadRequestException(OtpMessages.Error.OtpExpired);
        }

        // Check already verified or not
        if (userEntity?.otp?.isVerified) {
            throw new BadRequestException(OtpMessages.Error.AlreadyVerified);
        }

        // Compare input otp with stored otp
        // We need to format otp because we can't compare number with store otp string
        if (!await this.passwordService.comparePasswords(`${verifyOtpDto.otp}`, userEntity?.otp?.otp)) {
            throw new BadRequestException(OtpMessages.Error.IncorrectOtp);
        }

        // Mark otp verified
        await this.otpService.update({ uuid: userEntity?.otp?.uuid }, { isVerified: true });

        const isNewUser = !userEntity.isEmailVerified;
        if (isNewUser) {
            await this.userService.update({ uuid: userEntity.uuid }, { isEmailVerified: true });
            return new HttpResponseDto(AuthMessages.Success.EmailVerified);
        }

        // If user raised an request to forget; prompt user to reset password
        if (userEntity.isForgot) {
            return new HttpResponseDto(OtpMessages.Success.VerifiedAndReset);
        }

        // Reset resend otp attempts 
        await this.redisService.delete(RedisPrefix.RESEND_OTP_ATTEMPTS, userEntity.uuid);
        await this.redisService.delete(RedisPrefix.INCORRECT_PASSWORD_ATTEMPTS, userEntity.uuid);

        // Generate jwt access token for user payload
        const payload = {
            uuid: userEntity.uuid,
            role: userEntity.role
        }

        const accessToken = await this.jwtService.signAsync(payload);

        // Step to Implement One-Session-at-a-Time
        // await this.storeSession(userEntity.uuid, accessToken);

        await this.storeNSession(userEntity.uuid, accessToken, deviceInfo);

        const responseData = { accessToken, payload };

        return new HttpResponseDto(
            OtpMessages.Success.OtpVerified,
            responseData
        );
    }

    // Utils
    private isEmailVerified(isEmailVerified: boolean): void {
        if (!isEmailVerified) throw new BadRequestException(AuthMessages.Error.EmailNotVerified);
    }

    // Store session data in a Redis hash
    async storeNSession(userId: string, token: string, deviceInfo: IDeviceInfo): Promise<void> {
        const hashedToken = hashToken(token);
        const key = `${RedisPrefix.SESSION}:${userId}`;
        const sessionMeta = JSON.stringify(deviceInfo);
        await this.redisService.redisClient.hset(key, hashedToken, sessionMeta);
    }

    // Remove a session from Redis by token
    async removeOneSession(userId: string, token: string): Promise<void> {
        const key = `${RedisPrefix.SESSION}:${userId}`;
        const sessionField = hashToken(token);
        await this.redisService.redisClient.hdel(key, sessionField);
    }

    // Remove a session from Redis by token
    async removeAllSession(userId: string): Promise<void> {
        const key = `${RedisPrefix.SESSION}:${userId}`;
        await this.redisService.redisClient.del(key);
    }

    async isInvalidSession(userId: string, token: string) {
        const hashedToken = hashToken(token);
        const key = `${RedisPrefix.SESSION}:${userId}`;
        const sessionExists = await this.redisService.redisClient.hget(key, hashedToken);
        return sessionExists === null;
    }

    // Get the length of a Redis hash
    async getSessionCount(userId: string): Promise<number> {
        const key = `${RedisPrefix.SESSION}:${userId}`;
        return await this.redisService.redisClient.hlen(key) || 0;
    }

    async clearAllSessions(userId: string): Promise<void> {
        const key = `${RedisPrefix.SESSION}:${userId}`;
        await this.redisService.redisClient.del(key);
    }

    // One-Session-at-a-Time
    async storeSession(userId: string, token: string): Promise<void> {
        const hashedToken = hashToken(token);
        const ttl = getJwtExpiry(process.env.JWT_EXPIRATION_TIME ?? '1d');
        await this.redisService.setWithExpiry(RedisPrefix.SESSION, userId, hashedToken, ttl);
    }

    async isTokenValid(userId: string, token: string): Promise<boolean> {
        const hashedToken = hashToken(token);
        const sessionToken = await this.redisService.get(RedisPrefix.SESSION, userId);
        return hashedToken === sessionToken;
    }

    async deleteSession(userId: string): Promise<void> {
        await this.redisService.delete(RedisPrefix.SESSION, userId);
    }

    // Many-Session-at-a-Time
    async blacklistToken(token: string, ttl: number): Promise<void> {
        const hashedToken = hashToken(token);
        await this.redisService.setWithExpiry(RedisPrefix.BLACKLISTED_TOKEN, hashedToken, BLACKLISTED, ttl);
    }

    async isTokenBlacklisted(token: string): Promise<boolean> {
        const hashedToken = hashToken(token);
        const result = await this.redisService.get(RedisPrefix.BLACKLISTED_TOKEN, hashedToken);
        return result === BLACKLISTED;
    }

    async canResendOtp(userId: string): Promise<void> {
        // Use INCR and set expiry atomically if it's the first attempt
        const redisKey = `${RedisPrefix.RESEND_OTP_ATTEMPTS}:${userId}`;
        const attempts = await this.redisService.redisClient.incr(redisKey);

        if (attempts === 1) {
            // Set expiry only on the first creation
            await this.redisService.redisClient.expire(redisKey, RedisExpiry.ONE_DAY);
        }

        if (attempts >= this.maxResendOtpAttempts) {
            throw new ForbiddenException(`Maximum OTP resend attempts reached. Please try again later.`);
        }
    }

    async validateResendOtpAttempts(userId: string): Promise<void> {
        // const ttl = await this.redisService.redisClient.ttl(`${RedisPrefix.RESEND_OTP_ATTEMPTS}:${userId}`);
        // if (ttl > 0) {
        //     throw new ForbiddenException(`Maximum OTP resend attempts reached. Please try again again after ${Math.ceil(ttl / 60)} minutes.`);
        // }

        const attempts = +(await this.redisService.get(RedisPrefix.RESEND_OTP_ATTEMPTS, userId)) || 0;

        if (attempts >= this.maxPasswordAttempts) {
            throw new ForbiddenException(`Maximum OTP resend attempts reached. Please try again later.`);
        }
    }

    async handlePasswordAttempts(userId: string): Promise<void> {
        // Use INCR and set expiry atomically if it's the first attempt
        const redisKey = `${RedisPrefix.INCORRECT_PASSWORD_ATTEMPTS}:${userId}`;
        const attempts = await this.redisService.redisClient.incr(redisKey);

        if (attempts === 1) {
            // Set expiry only on the first creation
            await this.redisService.redisClient.expire(redisKey, RedisExpiry.ONE_DAY);
        }

        if (attempts >= this.maxPasswordAttempts) {
            throw new ForbiddenException("Account locked due to too many incorrect attempts. Please try again later.");
        }
    }

    async validatePasswordAttempts(userId: string): Promise<void> {
        // const ttl = await this.redisService.redisClient.ttl(`${RedisPrefix.INCORRECT_PASSWORD_ATTEMPTS}:${userId}`);
        // if (ttl > 0) {
        //     throw new ForbiddenException(`Your account is locked. Please try again after ${Math.ceil(ttl / 60)} minutes.`);
        // }

        const attempts = +(await this.redisService.get(RedisPrefix.INCORRECT_PASSWORD_ATTEMPTS, userId)) || 0;

        if (attempts >= this.maxPasswordAttempts) {
            throw new ForbiddenException("Your account is locked due to too many incorrect attempts. Please reset your password or try again later.");
        }
    }

    async canResetPassword(userId: string): Promise<void> {
        const redisKey = `${RedisPrefix.RESET_PASSWORD_ATTEMPTS}:${userId}`;
        const resetAttempts = await this.redisService.redisClient.incr(`${RedisPrefix.RESET_PASSWORD_ATTEMPTS}:${userId}`);

        if (resetAttempts === 1) {
            await this.redisService.redisClient.expire(redisKey, RedisExpiry.ONE_DAY);
        }

        if (resetAttempts >= this.maxResetAttempts) {
            throw new ForbiddenException("Password reset limit reached. Please try again later.");
        }
    }
}