import { ApiProperty } from "@nestjs/swagger";
import { Transform } from "class-transformer";
import { IsEmail, IsNotEmpty } from "class-validator";

export class BaseEmailDto {
    @ApiProperty()
    @IsEmail()
    @IsNotEmpty()
    @Transform(({ value }) => value?.toLocaleLowerCase())
    email: string;
}
