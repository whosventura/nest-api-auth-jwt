import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private jwtService: JwtService,
    ) { }

    async validarUsuario(username: string, password: string): Promise<any> {
        const user = await this.usersService.findOneByEmail(username);
        if (!user) {
            throw new UnauthorizedException('Usuário ou Senha inválidos');
        }
        if (user.password === password) {
            return await this.gerarToken(user);
        }
        throw new UnauthorizedException('Usuário ou Senha inválidos');
    }

    async gerarToken(payload: User) {
        const accessToken = this.jwtService.sign(
            { email: payload.email },
            {
                secret: process.env.JWT_SECRET_KEY,
                expiresIn: '30s',
            },
        );

        const refreshToken = this.jwtService.sign(
            { email: payload.email },
            {
                secret: process.env.JWT_SECRET_KEY,
                expiresIn: '60s',
            },
        );
        return { access_token: accessToken, refresh_token: refreshToken };
    }

    async reautenticar(body) {
        const payload: User = await this.verificarRefreshToken(body);
        return this.gerarToken(payload);
    }

    private async verificarRefreshToken(body) {
        const refreshToken = body.refresh_token;

        if (!refreshToken) {
            throw new NotFoundException('Usuário não encontrado');
        }

        const email = this.jwtService.decode(refreshToken)['email'];
        const usuario = await this.usersService.findOneByEmail(email);

        if (!usuario) {
            throw new NotFoundException('Usuário não encontrado');
        }

        try {
            this.jwtService.verify(refreshToken, {
                secret: process.env.JWT_SECRET_KEY,
            });
            return usuario;
        } catch (err) {
            if (err.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Assinatura Inválida');
            }
            if (err.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Token Expirado');
            }
            throw new UnauthorizedException(err.name);
        }
    }

}
