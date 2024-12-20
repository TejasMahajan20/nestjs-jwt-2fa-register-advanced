import { BaseEntity } from 'src/common/entities/base.entity';
import { Entity, Column, OneToOne, JoinColumn } from 'typeorm';
import { UserEntity } from './user.entity';

@Entity("otp")
export class OtpEntity extends BaseEntity {
  @Column({ nullable: false })
  otp: string;

  @Column({ default: false })
  isVerified: boolean;

  // One user can only have one otp
  @OneToOne(() => UserEntity, user => user.otp, { onDelete: "CASCADE" })
  @JoinColumn({ name: 'userId' })
  user: UserEntity;
}
