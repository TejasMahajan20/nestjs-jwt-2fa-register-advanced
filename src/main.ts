import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors();

  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,            // strips any properties not defined in the DTO
    forbidNonWhitelisted: true, // throws an error if extra properties are present,
    transform : true
  }));

  const config = new DocumentBuilder()
    .setTitle('Two Factor Basic JWT Authentication')
    .setExternalDoc('API JSON Documentation', 'swagger/json')
    .setVersion('1.0')
    .addServer(process.env.NODE_ORIGIN_LOCAL, 'Localhost')
    .addServer(process.env.NODE_ORIGIN_DEVELOPMENT, 'Development')
    .addServer(process.env.NODE_ORIGIN_PRODUCTION, 'Production')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      'access-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('swagger', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
    jsonDocumentUrl: 'swagger/json'
  });

  const port = +process.env.NODE_PORT || 3000;
  await app.listen(port, '0.0.0.0');

  const logger = new Logger('NestApplication');
  logger.debug(`This application is running on: ${await app.getUrl()}/swagger`);
}
bootstrap();
