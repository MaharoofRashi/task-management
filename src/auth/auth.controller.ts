import {
  Body,
  Controller,
  Post,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // User Registration
  @Post('register')
  @UsePipes(ValidationPipe)
  async register(@Body() body: any) {
    const { email, password, role } = body;
    return await this.authService.register(email, password, role);
  }

  // User Login
  @Post('login')
  @UsePipes(ValidationPipe)
  async login(@Body() body: any) {
    const user = await this.authService.validateUser(body.email, body.password);
    return this.authService.login(user);
  }
}
