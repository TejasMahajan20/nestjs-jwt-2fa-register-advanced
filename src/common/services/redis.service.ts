import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  redisClient: Redis;

  constructor(
    private readonly configService: ConfigService
  ) { }

  onModuleInit() {
    this.redisClient = new Redis({
      host: this.configService.get('QUEUE_HOST'),
      port: this.configService.get('QUEUE_PORT'),
    });
  }

  onModuleDestroy() {
    this.redisClient.disconnect();
  }

  // Prefix used to create folder like structure when accessing the Redis store
  async get(prefix: string, key: string): Promise<string | null> {
    return this.redisClient.get(`${prefix}:${key}`);
  }

  async set(prefix: string, key: string, value: string): Promise<void> {
    await this.redisClient.set(`${prefix}:${key}`, value);
  }

  async delete(prefix: string, key: string): Promise<void> {
    await this.redisClient.del(`${prefix}:${key}`);
  }

  async setWithExpiry(prefix: string, key: string, value: string, expiry: number): Promise<void> {
    await this.redisClient.set(`${prefix}:${key}`, value, 'EX', expiry);
  }

  async rpush(prefix: string, key: string, value: string): Promise<number> {
    return await this.redisClient.lpush(`user:${prefix}:${key}`, `${value}`);
  }

  async llen(prefix: string, key: string): Promise<number> {
    return await this.redisClient.llen(`user:${prefix}:${key}`);
}
}
