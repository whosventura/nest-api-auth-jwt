import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('/login')
    async login(@Body() body) {
        return this.authService.validarUsuario(body.username, body.password);
    }

    @Post('/refresh')
    reautenticar(@Body() body) {
        return this.authService.reautenticar(body);
    }

}
