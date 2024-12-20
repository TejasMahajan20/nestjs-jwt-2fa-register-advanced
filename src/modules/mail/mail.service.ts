import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailDataRequired, default as SendGrid } from '@sendgrid/mail';

@Injectable()
export class MailService {
    private readonly logger: Logger = new Logger(MailService.name);

    constructor(
        private readonly configService: ConfigService,
    ) {
        // NOTE : You have to set "esModuleInterop" to true in your tsconfig file to be able to use the default key in import.
        SendGrid.setApiKey(this.configService.get<string>('SENDGRID_API_KEY'));
    }

    private async send(mail: MailDataRequired): Promise<void> {
        try {
            await SendGrid.send(mail);
            this.logger.log(`Email successfully dispatched to ${mail.to}`);
        } catch (error) {
            this.logger.error('Error while sending email', error);
            throw error;
        }
    }

    async sendTestEmail(recipient: string, body = 'This is a test mail'): Promise<void> {
        const mail: MailDataRequired = {
            to: recipient,
            from: this.configService.get<string>('SENDGRID_SENDER_EMAIL_ID'),
            subject: 'Test email',
            content: [{ type: 'text/plain', value: body }],
        };
        await this.send(mail);
    }

    async sendEmailWithTemplate(recipient: string, body: string): Promise<void> {
        const mail: MailDataRequired = {
            to: recipient,
            from: this.configService.get<string>('SENDGRID_SENDER_EMAIL_ID'),
            templateId: 'Sendgrid_template_ID',
            dynamicTemplateData: { body, subject: 'Send Email with template' }, //The data to be used in the template
        };
        await this.send(mail);
    }
}
