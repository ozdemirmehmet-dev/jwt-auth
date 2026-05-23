import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import type { StringValue } from 'ms';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existing) {
      throw new ConflictException('Bu email zaten kayıtlı');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: hashedPassword,
      },
    });

    return { message: 'Kayıt başarılı', userId: user.id };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) throw new UnauthorizedException('Geçersiz bilgiler');

    const isPasswordValid = await bcrypt.compare(dto.password, user.password);
    if (!isPasswordValid) throw new UnauthorizedException('Geçersiz bilgiler');

    const tokens = await this.generateTokens(user.id, user.email);
    await this.saveRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async refresh(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync<{
        sub: number;
        email: string;
      }>(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });

      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('Geçersiz token');
      }

      const isValid = await bcrypt.compare(refreshToken, user.refreshToken);
      if (!isValid) throw new UnauthorizedException('Geçersiz token');

      const tokens = await this.generateTokens(user.id, user.email);
      await this.saveRefreshToken(user.id, tokens.refresh_token);

      return tokens;
    } catch {
      throw new UnauthorizedException('Geçersiz veya süresi dolmuş token');
    }
  }

  async logout(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
    return { message: 'Çıkış başarılı' };
  }

  private async generateTokens(userId: number, email: string) {
    const payload = { sub: userId, email };

    const accessSecret = process.env.JWT_ACCESS_SECRET;
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    const accessExpiresIn = (process.env.JWT_ACCESS_EXPIRES_IN ?? '15m') as StringValue;
    const refreshExpiresIn = (process.env.JWT_REFRESH_EXPIRES_IN ?? '7d') as StringValue;

    if (!accessSecret || !refreshSecret) {
      throw new Error('JWT secrets are not configured');
    }

    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: accessSecret,
        expiresIn: accessExpiresIn,
      }),
      this.jwtService.signAsync(payload, {
        secret: refreshSecret,
        expiresIn: refreshExpiresIn,
      }),
    ]);

    return { access_token, refresh_token };
  }

  private async saveRefreshToken(userId: number, refreshToken: string) {
    const hashed = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashed },
    });
  }
}
