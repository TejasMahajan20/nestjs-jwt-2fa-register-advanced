import { Body, Controller, Delete, HttpStatus, Post, Req, UnauthorizedException, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { HttpMessages } from 'src/common/constants/messages.constant';
import { AuthMessages, UserMessages } from './constants/messages.constant';
import { CreateUserDto } from './dto/create-user.dto';
import { SignInUserDto } from './dto/sign-in-user.dto';
import { BaseEmailDto } from './dto/base-email.dto';
import { AuthGuard } from './guards/auth.guard';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { UserService } from './services/user.service';
import { HttpResponseDto } from 'src/common/dto/http-response.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Request } from "express";
import { getIpAddress, getUserAgent } from './utils/helpers.util';
import { IDeviceInfo } from './interfaces/device-info.interface';

@Controller()
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService,
    ) { }

    @Post('register')
    @ApiOperation({
        summary: 'Register to admin portal',
        description: 'This endpoint will help us to register to admin portal.'
    })
    @ApiResponse({
        status: HttpStatus.CREATED,
        description: AuthMessages.Success.RegistrationSuccessful,
        schema: {
            example: new HttpResponseDto(AuthMessages.Success.RegistrationSuccessful),
        },
    })
    @ApiResponse({
        status: HttpStatus.BAD_REQUEST,
        description: UserMessages.Error.IsExist,
        schema: {
            example: {
                message: UserMessages.Error.IsExist,
                error: HttpMessages.Error.BadRequest,
                statusCode: HttpStatus.BAD_REQUEST
            }
        }
    })
    async register(@Body() createUserDto: CreateUserDto): Promise<HttpResponseDto<string>> {
        return await this.authService.register(createUserDto);
    }

    @Post('login')
    @ApiOperation({
        summary: 'Login to admin portal',
        description: 'This endpoint will help us to login to admin portal.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: AuthMessages.Success.LoginSuccessful })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async login(@Body() signInUserDto: SignInUserDto) {
        return await this.authService.login(signInUserDto);
    }

    // For many sessions at a time
    @Post('logout')
    @UseGuards(AuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({
        summary: 'Logout from admin portal',
        description: 'This endpoint will help us to logout from admin portal.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: AuthMessages.Success.LogoutSuccessful })
    @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: AuthMessages.Error.TokenNotFound })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async logout(@Req() req: Request) {
        const { token, exp } = req['tokenDetails'];
        const ttl = exp - Math.floor(Date.now() / 1000);
        return await this.authService.logout(token, ttl);
    }

    // For one sessions at a time
    @Post('logout')
    @UseGuards(AuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({
        summary: 'Logout from admin portal',
        description: 'This endpoint will help us to logout from admin portal.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: AuthMessages.Success.LogoutSuccessful })
    @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: AuthMessages.Error.TokenNotFound })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async logout_(@Req() req: Request) {
        const { uuid: userId } = req['tokenDetails'];
        return await this.authService.logout_(userId);
    }

    @Delete('session')
    @UseGuards(AuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({
        summary: 'Remove selected session',
        description: 'This endpoint will help us to remove selected session.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: AuthMessages.Success.SessionRemoved })
    @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: AuthMessages.Error.TokenNotFound })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async removeOneNSession(@Req() req: Request) {
        const { uuid: userId, token } = req['tokenDetails'];
        await this.authService.removeOneSession(userId, token);
        return new HttpResponseDto(AuthMessages.Success.SessionRemoved);
    }

    @Post('verify-otp')
    @ApiOperation({
        summary: 'Verify verification key using email and otp.',
        description: 'This endpoint will prompt you email and otp to authenticate you'
    })
    async verifyOtp(@Req() req: Request, @Body() verifyOtpDto: VerifyOtpDto) {
        const deviceInfo : IDeviceInfo = {
            ip: getIpAddress(req),
            userAgent: getUserAgent(req),
            loggedInAt: new Date()
        }
        return await this.authService.verifyOtp(verifyOtpDto, deviceInfo);
    }

    @Post('resend-otp')
    @ApiOperation({
        summary: 'Send verification key.',
        description: 'This endpoint will prompt you email and password to resent verification key.'
    })
    async resendOtp(@Body() resendOtpDto: BaseEmailDto) {
        return await this.authService.resendOtp(resendOtpDto);
    }

    @Post('forgot-password')
    @ApiOperation({
        summary: 'Forgot password',
        description: 'This endpoint will help us to recover your account.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: UserMessages.Success.Invited })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async forgotPassword(@Body() forgotPasswordDto: BaseEmailDto) {
        return await this.authService.forgotPassword(forgotPasswordDto);
    }

    @Post('reset-password')
    @ApiOperation({
        summary: 'Reset old password.',
        description: 'This endpoint will prompt you email and new password to reset your old password.'
    })
    async resetPassword(@Body() resetPasswordDto: SignInUserDto) {
        return await this.authService.resetPassword(resetPasswordDto);
    }

    @Post('update-password')
    @UseGuards(AuthGuard)
    @ApiBearerAuth('access-token')
    @ApiOperation({
        summary: 'Update password',
        description: 'This endpoint will help us to update password.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: UserMessages.Success.Invited })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async updatePassword(
        @Req() req: Request,
        @Body() updatePasswordDto: UpdatePasswordDto
    ) {
        const { uuid: userId } = req['user'];
        return await this.authService.updatePassword(userId, updatePasswordDto);
    }

    // Development Purpose
    @Delete()
    @ApiOperation({
        summary: 'Delete all users',
        description: 'This endpoint will help you to delete all users.'
    })
    async delete() {
        await this.userService.deleteAll();
        return "All users deleted.";
    }

}
