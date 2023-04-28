import { BadRequestException, Body, Controller, Post } from '@nestjs/common';
import { UsersService } from './users.service';
import { UserCreateDto } from './models/user-create.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post('register')
  async register(@Body() userCreateDto: UserCreateDto) {
    if (userCreateDto.password !== userCreateDto.confirmPassword) {
      throw new BadRequestException('Passwords do not match!');
    }
    const newUser = await this.userService.createUser(userCreateDto);
    return newUser;
  } 
}
