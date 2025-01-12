import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsStrongPassword, Validate } from "class-validator";
import { BaseEmailDto } from "./base-email.dto";
import { PasswordMatch } from "../validators/password-match.validator copy";

export class ResetPasswordDto extends BaseEmailDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsStrongPassword()
    @Validate(PasswordMatch)
    newPassword: string;

    @ApiProperty()
    @IsNotEmpty()
    @IsStrongPassword()
    confirmNewPassword: string;
}
