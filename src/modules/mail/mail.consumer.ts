import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';

@Processor('mail')
export class MailConsumer extends WorkerHost {
    private readonly logger = new Logger(MailConsumer.name);

    async process(job: Job<any, any, string>): Promise<any> {

        return {};
    }
}
