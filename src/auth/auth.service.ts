import { BadRequestException, Inject, Injectable, NotFoundException, UnauthorizedException, forwardRef } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Request } from 'express';
import { User } from 'src/users/entities/users.entity';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './model/login.dto';
import { Payload } from './payload/payload.interface';
import { ConfigService } from '@nestjs/config';
import { RefreshTokenDto } from './model/refreshToken.dto';


@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,  
    private readonly configService: ConfigService,
  ) {}
  
  async validateUser(loginDto: LoginDto): Promise<User> {
    const user = await this.userService.findUserByEmail(loginDto.email);

    if (!user) {
      throw new NotFoundException('User not found!')
    }

    if (!await bcrypt.compare(loginDto.password, user.password)) {
      throw new BadRequestException('Invalid credentials!');
    }

    return user;
  } 

  async refresh(refreshTokenDto: RefreshTokenDto): Promise<{ accessToken: string }> {
    const { refresh_token } = refreshTokenDto;

    // Verify refresh token
    // JWT Refresh Token 검증 로직
    const decodedRefreshToken = this.jwtService.verify(refresh_token, { secret: process.env.JWT_REFRESH_SECRET }) as Payload;

    // Check if user exists
    const userId = decodedRefreshToken.id;
    const user = await this.userService.getUserIfRefreshTokenMatches(refresh_token, userId);
    if (!user) {
      throw new UnauthorizedException('Invalid user!')
    }

    // Generate new access token
    const accessToken = await this.generateAccessToken(user);

    return {accessToken};
  }

  async generateAccessToken(user: User): Promise<string> {
    const payload: Payload = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    }
    return this.jwtService.sign(payload);
  }

  async generateRefreshToken(user: User): Promise<string> {
    const payload: Payload = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    }
    return this.jwtService.signAsync({id: payload.id}, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION_TIME'),
    });
  }

  async userId(req: Request): Promise<number> {
    const cookie = req.cookies['access_token'];

    const data = await this.jwtService.verifyAsync(cookie);

    return data['id'];
  }
}
