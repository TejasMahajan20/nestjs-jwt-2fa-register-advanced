import { IntersectionType } from "@nestjs/swagger";
import { BaseEmailDto } from "./base-email.dto";
import { BasePasswordDto } from "./base-password.dto";

export class CreateUserDto extends IntersectionType(BaseEmailDto, BasePasswordDto) {
    role?: string;
}