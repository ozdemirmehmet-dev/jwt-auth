# jwt-auth

NestJS ile JWT kimlik doğrulama sistemi.

## Özellikler
- Register / Login
- JWT Access Token (15 dakika)
- Refresh Token (7 gün, veritabanında saklanır)
- Korumalı route'lar (Guard)
- Bcrypt ile şifre hashleme

## Teknolojiler
- NestJS
- Prisma ORM
- PostgreSQL (Docker)
- Passport.js + JWT

## Kurulum
```bash
docker run --name nestjs-postgres \
  -e POSTGRES_USER=nestuser \
  -e POSTGRES_PASSWORD=nestpass \
  -e POSTGRES_DB=nestdb \
  -p 5432:5432 -d postgres:16

npm install
npx prisma migrate dev
npm run start:dev
```

## Detaylı Rehber
`NestJS-JWT-Auth-Rehber.docx` dosyasına bakın.