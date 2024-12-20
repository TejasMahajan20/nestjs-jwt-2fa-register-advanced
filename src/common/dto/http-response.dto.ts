import { ApiProperty } from "@nestjs/swagger";
import { HttpResponseStatus } from "../enum/http-response-status.enum";

export class HttpResponseDto<T> {
  @ApiProperty({ enum: HttpResponseStatus })
  status: HttpResponseStatus = HttpResponseStatus.SUCCESS; // Default to 'Success'

  @ApiProperty({ required: false, description: 'Data payload, can be null' })
  data?: T;

  @ApiProperty({ description: 'Message describing the response' })
  message: string;

  @ApiProperty({ required: false, description: 'Additional Properties' })
  meta?: object;

  constructor(message: string, data: T = null, status: HttpResponseStatus = HttpResponseStatus.SUCCESS, meta : object = null) { // status has default value
    this.message = message;
    this.data = data;
    this.status = status;
    this.meta = meta;
  }
}
