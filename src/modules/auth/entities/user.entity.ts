import { BaseEntity } from 'src/common/entities/base.entity';
import { Column, Entity, OneToOne } from 'typeorm';
import { OtpEntity } from './otp.entity';
import { Role } from '../enum/role.enum';

// Credentials table
@Entity("user_auth")
export class UserEntity extends BaseEntity {
  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ nullable: false })
  password: string;

  @Column({ nullable: true, enum: Role, type: 'enum' })
  role: Role;

  @Column({ default: false })
  isLoggedBefore: boolean;

  @Column({ default: false })
  isForgot: boolean;

  @Column({ default: false })
  isEmailVerified: boolean;

  // One user can only have one otp
  @OneToOne(() => OtpEntity, otp => otp.user, { onDelete: "CASCADE" })
  otp: OtpEntity;
}
