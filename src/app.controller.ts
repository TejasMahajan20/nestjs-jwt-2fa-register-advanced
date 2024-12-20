import { Controller, Get, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { GenericMessages } from './common/constants/messages.constant';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('health')
  @ApiOperation({
    summary: 'Check health of api',
    description: 'This endpoint will check health of api.'
  })
  @ApiResponse({ status: HttpStatus.CREATED, description: GenericMessages.Success.ServiceIsHealthly })
  health(): object {
    return this.appService.health();
  }
}
