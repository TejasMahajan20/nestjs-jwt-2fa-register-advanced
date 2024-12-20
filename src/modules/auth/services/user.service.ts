import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { GenericCrudService } from 'src/common/services/generic-crud.service';
import { InjectRepository } from '@nestjs/typeorm';
import { LessThanOrEqual, Repository } from 'typeorm';
import { UserEntity } from '../entities/user.entity';
import { UserMessages } from '../constants/messages.constant';

@Injectable()
export class UserService extends GenericCrudService<UserEntity> {
    private readonly logger: Logger = new Logger(UserService.name);

    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
    ) {
        super(userRepository);
    }

    async isUserExist(email: string) {
        const userEntity = await this.findOne({ email });
        if (userEntity) throw new BadRequestException(UserMessages.Error.IsExist);
        return userEntity;
    }

    async validateUserByEmail(email: string) {
        const userEntity = await this.findOne({ email }, ['otp']);
        if (!userEntity) throw new NotFoundException(UserMessages.Error.NotFound);
        return userEntity;
    }

    async validateUserByUuid(uuid: string) {
        const userEntity = await this.findOne({ uuid });
        if (!userEntity) throw new NotFoundException(UserMessages.Error.NotFound);
        return userEntity;
    }
    
    // Delete user due to prolonged inactivity.
    async deleteStaleUnverifiedUsers() {
        const oneDayAgo = new Date();
        oneDayAgo.setDate(oneDayAgo.getDate() - 1);

        const result = await this.delete({
            createdAt: LessThanOrEqual(oneDayAgo),
            isEmailVerified: false
        });

        const deletedCount = result.affected || 0;

        if (deletedCount > 0) {
            this.logger.log(
                `Removed ${deletedCount} unverified users created before ${oneDayAgo.toISOString()} successfully.`
            );
        } else {
            this.logger.log('No stale unverified users found.');
        }
    }
}
