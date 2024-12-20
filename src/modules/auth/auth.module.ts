import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from './entities/user.entity';
import { PasswordService } from './services/password.service';
import { UserService } from './services/user.service';
import { OtpService } from './services/otp.service';
import { OtpEntity } from './entities/otp.entity';
import { MailModule } from '../mail/mail.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      UserEntity,
      OtpEntity
    ]),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET_KEY'),
        signOptions: {
          expiresIn: config.get<string>('JWT_EXPIRATION_TIME'),
        },
      }),
    }),
    MailModule
  ],
  controllers: [AuthController],
  providers: [AuthService, UserService, OtpService, PasswordService],
  exports: [UserService]
})
export class AuthModule { }
