import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import typeOrmConfig from './typeorm.config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [UsersModule, TypeOrmModule.forRoot(typeOrmConfig), AuthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
