import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsStrongPassword } from "class-validator";

export class BasePasswordDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsStrongPassword()
    password: string;
}
