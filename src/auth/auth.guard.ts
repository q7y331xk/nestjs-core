import { jwtConstant } from './../secret/jwt.secret';
import {
  CanActivate,
  ExecutionContext,
  HttpStatus,
  mixin,
  Type,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as jwt from 'jsonwebtoken';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import { ResponseException } from 'src/types/http-response.type';
import { stringFunc } from 'src/funcs/string';
import { adminUserConstant } from 'src/secret/admin-user.secret';
import { Role } from 'src/types/role.type';

export const AuthGuard = (role?: string): Type<CanActivate> => {
  class AuthGuardMixin implements CanActivate {
    constructor(
      @InjectRepository(User)
      private readonly userRepository: Repository<User>,
    ) {}
  
    // 토큰 정보가 아예 없거나, 정상적일 때만 진행
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const req = context.switchToHttp().getRequest();
      const { authorization } = req.headers;
      const bearerKey = this.checkBearerToken(authorization)
      if (!bearerKey) throw new ResponseException(undefined, 'unauthentication: key error', HttpStatus.UNAUTHORIZED)

      req.user = this.validateToken(bearerKey);
      if (role && role === Role.Admin) {
        const adminUser = this.isAdmin(req.user.name)
        if(!adminUser) {
          throw new ResponseException(
            { unauthorized: 'admin' },
            'Forbidden',
            HttpStatus.FORBIDDEN,
          );
        }
      }
      const user = await this.userRepository.findOne({
        where: { id: req.user.id },
      });
      // 만약 비밀번호 변경이 발생하였으면 기존 토큰 만료 처리
      if (
        user.passwordVersion &&
        user.passwordVersion !== req.user.passwordVersion
      ) {
        throw new ResponseException(
          undefined,
          '비밀번호가 변경되었습니다.',
          HttpStatus.UNAUTHORIZED,
        );
      }
      return true;
    }
  
    checkBearerToken(authorization: string) {
      const [ type, key ] = authorization.split(' ')
      if (type !== "Bearer") { throw new ResponseException(undefined, "this token is not bearer type", HttpStatus.UNAUTHORIZED)}
      return key;
    }
  
    // 토큰 검증
    validateToken(bearerKey: string): jwt.JwtPayload | string {
      try {
        return jwt.verify(bearerKey, jwtConstant.secret);
      } catch ({ message }) {
        switch (message) {
          case 'invalid token':
          case 'jwt malformed': {
            throw new ResponseException(
              undefined,
              '유효하지 않은 토큰입니다.',
              HttpStatus.UNAUTHORIZED,
            );
          }
          case 'jwt expired': {
            throw new ResponseException(undefined, '토큰이 만료되었습니다.', HttpStatus.GONE);
          }
          default: {
            throw new ResponseException(undefined, '기타', HttpStatus.INTERNAL_SERVER_ERROR);
          }
        }
      }
    }

    isAdmin(username: string) {
      if (stringFunc.compareOneWithMany(username, adminUserConstant.list)) return true;
      else return false
    };
  }

  const guard = mixin(AuthGuardMixin);
  return guard;
}
