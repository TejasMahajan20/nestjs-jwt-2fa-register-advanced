import { Body, Controller, Delete, HttpStatus, Post, Req, Request, UseGuards } from '@nestjs/common';
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

    @Post('logout')
    @ApiOperation({
        summary: 'Logout from admin portal',
        description: 'This endpoint will help us to logout from admin portal.'
    })
    @ApiResponse({ status: HttpStatus.CREATED, description: AuthMessages.Success.LoginSuccessful })
    @ApiResponse({ status: HttpStatus.INTERNAL_SERVER_ERROR, description: HttpMessages.Error.InternalServerError })
    async logout(@Body() signInUserDto: SignInUserDto) {
        return await this.authService.login(signInUserDto);
    }

    @Post('verify-otp')
    @ApiOperation({
        summary: 'Verify verification key using email and otp.',
        description: 'This endpoint will prompt you email and otp to authenticate you'
    })
    async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
        return await this.authService.verifyOtp(verifyOtpDto);
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
