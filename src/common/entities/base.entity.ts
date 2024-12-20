import { PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';

// This will be used with any table
export abstract class BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  uuid: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ nullable: true })
  createdBy: string;

  @UpdateDateColumn({ type: 'timestamp', nullable: true })
  modifiedAt: Date;

  @Column({ nullable: true })
  modifiedBy: string;

  @Column({ default: false })
  isDeleted: boolean;

  @DeleteDateColumn({ type: 'timestamp', nullable: true })
  deletedAt: Date;
}
