import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, IsStrongPassword, Validate } from "class-validator";
import { AllPasswordMatch } from "../validators/all-password-match.validator";

export class UpdatePasswordDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsString()
    oldPassword: string;

    @ApiProperty()
    @IsNotEmpty()
    @IsStrongPassword()
    @Validate(AllPasswordMatch)
    newPassword: string;

    @ApiProperty()
    @IsNotEmpty()
    @IsStrongPassword()
    confirmNewPassword: string;
}
