import {
    ValidatorConstraint,
    ValidatorConstraintInterface,
    ValidationArguments,
    registerDecorator,
    ValidationOptions,
} from 'class-validator';

// Validation Logic
@ValidatorConstraint({ name: 'isLength', async: false })
export class IsLengthConstraint implements ValidatorConstraintInterface {
    validate(value: string | number, args: ValidationArguments) {
        const [length] = args.constraints;
        return value.toString().length === length;
    }

    defaultMessage(args: ValidationArguments) {
        const [length] = args.constraints;
        return `Value must be exactly ${length} characters long`;
    }
}

// Decorator
export function IsLength(length: number, validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            constraints: [length],
            validator: IsLengthConstraint,
        });
    };
}
