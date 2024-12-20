export const UserMessages = {
    Success: {
        Created: 'Verification link sent to your email.',
        PasswordUpdated: 'Password updated successfully.',
        Deleted: 'User deleted successfully.',
        Invited: 'User invited successfully.',
        ProfileRetrieved: 'User profile retrieved.',
    },
    Error: {
        IsExist: 'User already exists.',
        NotFound: 'User not found.',
        IncorrectPassword: 'Incorrect password.',
        IncorrectOldPassword: 'Incorrect old password.',
        SameAsOldPassword: 'Old and new passwords must be different.',
        PasswordAlreadyUpdated: 'Password has already been updated.',
        PasswordUpdateError: 'Error updating password.',
        CreateError: 'Failed to create user.',
        ReadError: 'Failed to find user.',
        UpdateError: 'Failed to update user.',
        DeleteError: 'Failed to delete user.',
    }
};

export const OtpMessages = {
    Success: {
        OtpSent: 'OTP sent to your email for verification.',
        EmailVerificationSent : 'Continue registration. We’ve sent a new OTP to your email for verification.',
        OtpSentAndVerify: 'OTP sent. Please verify and reset your password.',
        OtpVerified: 'Login successful.',
        VerifiedAndUpdate: 'OTP verified. Please set a new password.',
        VerifiedAndReset: 'OTP verified. Please reset your password.',
    },
    Error: {
        IsExist: 'User already exists.',
        NotVerified: 'Complete OTP verification before proceeding.',
        AlreadyVerified: 'OTP has already been verified.',
        SendError: 'Failed to send OTP.',
        IncorrectOtp: 'Incorrect OTP.',
        OtpExpired: 'OTP has expired.',
        VerifyError: 'Failed to verify OTP.',
    }
};

export const AuthMessages = {
    Success: {
        RegistrationSuccessful: 'Registration successful! A verification code has been sent to your email.',
        LoginSuccessful: 'Login successful.',
        LogoutSuccessful: 'Logout successful.',
        EmailVerified: 'Email verified successfully.',
    },
    Error: {
        RegistrationFailed: 'An error occurred during registration.',
        LoginFailed: 'An error occurred during login.',
        LogoutFailed: 'An error occurred during logout.',
        TokenNotFound: 'Token not found',
        InvalidToken: 'Invalid token.',
        InvalidTokenOrAlreadyLoggedOut: 'Invalid token or already logged out.',
        AccessTokenRequired: 'Access token required to authenticate the request.',
        TokenExpired: 'Token expired.',
        EmailNotVerified: 'Email verification pending.',
    }
};