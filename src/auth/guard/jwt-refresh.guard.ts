import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { User } from 'src/users/entities/users.entity';

@Injectable()
export class JwtRefreshGuard extends AuthGuard('jwt-refresh-token') {}