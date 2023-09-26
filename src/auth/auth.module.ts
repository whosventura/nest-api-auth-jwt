import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import { AuthService } from './auth.service';
import { LocalStrategy } from './local.auth';
import { AuthController } from './auth.controller';


@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    PassportModule,
    JwtModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, UsersService, LocalStrategy],
  exports: [AuthService]
})
export class AuthModule { }
