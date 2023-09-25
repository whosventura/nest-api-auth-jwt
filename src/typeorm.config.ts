import { TypeOrmModuleOptions } from '@nestjs/typeorm';

const typeOrmConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'postgres',
  password: 'adm',
  database: 'nest-api-auth-jwt',
  entities: [__dirname + '/**/*.entity.{js,ts}'],
  synchronize: true,
};

export default typeOrmConfig;
