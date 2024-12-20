import { Injectable } from '@nestjs/common';
import { GenericMessages } from './common/constants/messages.constant';
import { HttpResponseDto } from './common/dto/http-response.dto';

@Injectable()
export class AppService {
  health(): object {
    return new HttpResponseDto(GenericMessages.Success.ServiceIsHealthly);
  }
}
