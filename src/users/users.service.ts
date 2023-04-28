import { BadRequestException, HttpException, HttpStatus, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UsersRepository } from './repositories/users.repository';
import { UserCreateDto } from 'src/users/models/user-create.dto';
import { User } from './entities/users.entity';
import { UserUpdateDto } from './models/user-update.dto';

@Injectable()
export class UsersService {
  constructor(private readonly userRepository: UsersRepository) {}

  async createUser(newUser: UserCreateDto): Promise<User> {
    const userFind: User = await this.userRepository.findOne({
      where: {
        email: newUser.email,
      }
    });
    if (userFind) {
      throw new HttpException('UserEmail already used!', HttpStatus.BAD_REQUEST);
    }

    const saltOrRounds = 12;
    const hashedPassword = await this.hashPassword(newUser.password, saltOrRounds);
    return this.userRepository.save({
      ...newUser,
      password: hashedPassword,
      confirmPassword: hashedPassword
    });
  }

  private async hashPassword(password: string, saltOrRounds: number): Promise<string> {
    return bcrypt.hash(password, saltOrRounds);
  }

  async findUserByEmail(email: string): Promise<User> {
    return await this.userRepository.findOne({
      where: {
        email: email,
      }
    })
  }

  async findUserById(id: number): Promise<User> {
    return await this.userRepository.findOne({
      where: {
        id: id
      },
    })
  }

  async updateUserInfo(id: number, data: UserUpdateDto): Promise<User> {
    const user = await this.findUserById(id);

    if (!user) {
      throw new NotFoundException('해당 id의 유저 정보는 존재하지 않습니다.');
    }

    const findEmail = await this.findUserByEmail(data.email);

    if (findEmail && findEmail.id !== user.id) {
      throw new HttpException('Username already used!', HttpStatus.BAD_GATEWAY);
    }

    await this.userRepository.update(id, data);

    const updatedUser = await this.userRepository.findOne({
      where: {
        id,
      }
    });
    return updatedUser;
  }

  async deleteUser(id: number): Promise<any> {
    return this.userRepository.delete(id);
  }

  async getCurrentRefreshToken(refreshToken: string) {
    const saltOrRounds = 10;
    const currentRefreshToken = await bcrypt.hash(refreshToken, saltOrRounds);
    return currentRefreshToken;
  }

  async setCurrentRefreshToken(refreshToken: string, userId: number) {
    const currentRefreshToken = await this.getCurrentRefreshToken(refreshToken);
    console.log(currentRefreshToken, "hhhhhhhhhhhhhhhhhhhhhhhhhh");
    await this.userRepository.update(userId, {
      currentRefreshToken: currentRefreshToken,
    });
  }

  async getUserIfRefreshTokenMatches(refreshToken: string, userId: number): Promise<User> {
    const user: User = await this.findUserById(userId);

    if (!user.currentRefreshToken) {
      return null;
    }

    const isRefreshTokenMatching = await bcrypt.compare(
      refreshToken,
      user.currentRefreshToken
    );

    if (isRefreshTokenMatching) {
      return user;
    } 
  }

  async removeRefreshToken(userId: number): Promise<any> {
    return await this.userRepository.update(userId, {
      currentRefreshToken: null,
    });
  }
}
