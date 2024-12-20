import { Injectable } from '@nestjs/common';
import { Repository, DeepPartial, FindOptionsWhere, FindManyOptions, In, DeleteResult, UpdateResult } from 'typeorm';
import { QueryDeepPartialEntity } from 'typeorm/query-builder/QueryPartialEntity';

@Injectable()
export class GenericCrudService<T> {
  constructor(protected readonly repository: Repository<T>) { }

  async create(createDto: DeepPartial<T>): Promise<T> {
    const entity = this.repository.create(createDto);
    return await this.repository.save(entity);
  }

  async createMany(createManyDto: DeepPartial<T>[]): Promise<T[]> {
    const entities = this.repository.create(createManyDto);
    return await this.repository.save(entities);
  }

  async findOne(conditions: FindOptionsWhere<T>, relations?: string[]): Promise<T | null> {
    return await this.repository.findOne({
      where: conditions,
      relations: relations || []
    });
  }

  async validate(conditions: FindOptionsWhere<T>): Promise<boolean> {
    return await this.repository.existsBy(conditions);
  }

  async findAll(options?: FindManyOptions<T>): Promise<T[]> {
    return await this.repository.find(options);
  }

  // Generic method to find entities by a specific field and an array of values
  async findAllBy<K extends keyof T>(field: K, values: T[K][]): Promise<T[]> {
    return await this.repository.find({
      where: {
        [field]: In(values),
      } as FindOptionsWhere<T>,
    });
  }

  async update(id: any, entity: QueryDeepPartialEntity<T>): Promise<UpdateResult> {
    return await this.repository.update(id, entity);
  }

  async delete(id: any): Promise<DeleteResult> {
    return await this.repository.delete(id);
  }

  async deleteAll(where?: FindOptionsWhere<T>): Promise<DeleteResult> {
    return await this.repository.delete(where || {});
  }

  async softDelete(id: any): Promise<void> {
    await this.repository.softDelete(id);
  }
}
