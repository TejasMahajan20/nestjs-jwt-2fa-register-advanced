import { ApiProperty } from "@nestjs/swagger";
import { IsInt } from "class-validator";
import { BaseEmailDto } from "./base-email.dto";
import { IsLength } from "../validators/is-length.constraint";

export class VerifyOtpDto extends BaseEmailDto {
    @ApiProperty()
    @IsInt()
    @IsLength(6, { message: 'OTP must be exactly 6 digits long' })
    otp: number;
}

