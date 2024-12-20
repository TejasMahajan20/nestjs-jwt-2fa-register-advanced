import { ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface } from "class-validator";

@ValidatorConstraint({ name: "PasswordMatch", async: false })
export class PasswordMatch implements ValidatorConstraintInterface {
    validate(newPassword: string, args: ValidationArguments) {
        const { object } = args;
        return (
            newPassword === object['confirmNewPassword'] && 
            newPassword !== object['oldPassword']
        );
    }

    defaultMessage(args: ValidationArguments) {
        return "New password and confirm new password must match, and should not be the same as the old password.";
    }
}