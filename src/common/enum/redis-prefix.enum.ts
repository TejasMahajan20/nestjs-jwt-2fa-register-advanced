export enum RedisPrefix {
    OTP = 'otp',
    SESSION = 'session',
    BLACKLISTED_TOKEN = 'blacklisted_token',
    INCORRECT_PASSWORD_ATTEMPTS = 'incorrect_password_attempts',
    RESET_PASSWORD_ATTEMPTS = 'reset_password_attempts',
    RESEND_OTP_ATTEMPTS = 'resend_otp_attempts',
}