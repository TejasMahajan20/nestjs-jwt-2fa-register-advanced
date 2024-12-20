import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty } from "class-validator";
import { BaseEmailDto } from "./base-email.dto";

export class SignInUserDto extends BaseEmailDto {
    @ApiProperty()
    @IsNotEmpty()
    password: string;
}