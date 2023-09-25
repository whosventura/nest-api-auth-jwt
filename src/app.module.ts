import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import typeOrmConfig from './typeorm.config';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [UsersModule, TypeOrmModule.forRoot(typeOrmConfig)],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
