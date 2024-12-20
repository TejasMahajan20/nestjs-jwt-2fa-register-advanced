import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { BullModule } from '@nestjs/bullmq';
import { MailConsumer } from './mail.consumer';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'mail',
    })
  ],
  providers: [MailService, MailConsumer],
  exports: [MailService],
})
export class MailModule { }
