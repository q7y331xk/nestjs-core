import { User } from 'src/user/entities/user.entity';
import { PickType } from '@nestjs/mapped-types';

export class CreateUserDto extends PickType(User, [
  'authType',
  'name',
  'password',
]) {}
