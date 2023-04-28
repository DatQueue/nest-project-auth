import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { AuthGuard } from "@nestjs/passport";
import { AuthService } from "../auth.service";

@Injectable()
export class JwtAccessAuthGuard extends AuthGuard('jwt-access-token') implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService,
  ) {
    super();
  }
  async canActivate(
    context: ExecutionContext,
  ): Promise<any> {
    try {
      const request = context.switchToHttp().getRequest();
      const access_token = request.cookies['access_token']; 
      return this.jwtService.verify(access_token);
    }catch(err) {
      return false;
    }
  }
}