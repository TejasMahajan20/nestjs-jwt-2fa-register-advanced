import { Injectable } from '@nestjs/common';
import { GenericCrudService } from 'src/common/services/generic-crud.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { OtpEntity } from '../entities/otp.entity';

@Injectable()
export class OtpService extends GenericCrudService<OtpEntity> {
    constructor(
        @InjectRepository(OtpEntity)
        private readonly otpRepository: Repository<OtpEntity>,
    ) {
        super(otpRepository);
    }

    generateNumericOTP(length = 6): string {
        // Ensure the length is reasonable
        if (length < 1) {
            throw new Error('OTP length must be at least 1');
        }

        // Generate the first digit separately to ensure it is not zero
        const firstDigit = Math.floor(Math.random() * 9) + 1; // This ensures the first digit is between 1 and 9

        // Generate the remaining digits
        const maxNumber = Math.pow(10, length - 1);
        const randomNumber = Math.floor(Math.random() * maxNumber);

        // Concatenate the first digit with the remaining digits, padding with leading zeros if necessary
        const remainingDigits = randomNumber.toString().padStart(length - 1, '0');

        // Combine the first digit with the remaining digits
        return firstDigit.toString() + remainingDigits;
    }

    isExpired(timestamp: Date): boolean {
        // Get the current time
        const currentTime = new Date();

        // Calculate expiration time (2 minutes later)
        const expirationTime = timestamp.getTime() + 2 * 60 * 1000;

        // Check if the current time is past the expiration time
        return currentTime.getTime() > expirationTime;
    }

    isMoreThanTwoMinutes(timestamp: Date): boolean {
        // Get the current time
        const currentTime = new Date();

        // Calculate the time when it would have been 2 minutes after the timestamp
        const twoMinutesLater = timestamp.getTime() + 2 * 60 * 1000;

        // Check if the current time is past the "two minutes later" time
        return currentTime.getTime() > twoMinutesLater;
    }

    getTimeRemaining(timestamp: Date): number {
        const currentTime = new Date();
        const twoMinutesLater = timestamp.getTime() + 2 * 60 * 1000;
        const timeRemaining = twoMinutesLater - currentTime.getTime();

        // Convert milliseconds to seconds and return the remaining time
        return Math.ceil(timeRemaining / 1000); // Time in seconds
    }

}
