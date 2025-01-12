import { IntersectionType } from "@nestjs/swagger";
import { BaseEmailDto } from "./base-email.dto";
import { BasePasswordDto } from "./base-password.dto";
import { Role } from "../enum/role.enum";

export class CreateUserDto extends IntersectionType(BaseEmailDto, BasePasswordDto) {
    role?: Role;
}