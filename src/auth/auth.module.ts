import { Module, forwardRef } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from 'src/users/users.module';
import { UsersService } from 'src/users/users.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/users.entity';
import { TypeOrmExModule } from 'src/common/respository-module/typeorm-ex.decorator';
import { UsersRepository } from 'src/users/repositories/users.repository';
import { JwtAccessStrategy } from './strategy/jwt-access.strategy';
import { JwtAccessAuthGuard } from './guard/jwt-access.guard';
import { JwtRefreshStrategy } from './strategy/jwt-refresh.strategy';
import { JwtRefreshGuard } from './guard/jwt-refresh.guard';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    TypeOrmExModule.forCustomRepository([UsersRepository]),
    PassportModule.register({}),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRATION_TIME'),
        } 
      }),
      inject: [ConfigService],
    }),
    forwardRef(() => UsersModule),
  ],
  controllers: [AuthController],
  providers: [AuthService, UsersService, JwtAccessStrategy, JwtRefreshStrategy, JwtAccessAuthGuard, JwtRefreshGuard],
})
export class AuthModule {}
