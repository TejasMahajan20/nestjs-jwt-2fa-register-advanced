import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job, tryCatch } from 'bullmq';
import { MailService } from './mail.service';

@Processor('mail')
export class MailConsumer extends WorkerHost {
    private readonly logger = new Logger(MailConsumer.name);

    constructor(
        private readonly mailService: MailService,
    ) {
        super();
    }

    async process(job: Job<any, any, string>): Promise<any> {
        const { recipient, body } = job.data;
        try {
            await this.mailService.sendTestEmail(recipient, body);
        } catch (error) {
            console.error(error);
        }
        return {};
    }
}
