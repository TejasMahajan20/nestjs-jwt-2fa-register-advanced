import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, IsStrongPassword, Validate } from "class-validator";
import { PasswordMatch } from "../validators/password-match.validator";

export class UpdatePasswordDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsString()
    oldPassword: string;

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
