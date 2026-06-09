# Password Manager Go Backend

This folder is a Go implementation of the existing Node/Express backend.
It uses Gin for routing and handlers, which gives the backend an Express-like style in Go.

## Run

```powershell
cd go-backend
go mod tidy
go run ./cmd/server
```

## Create keys

Run this command to create a strong JWT secret and encryption key:

```powershell
go run ./cmd/keygen
```

Copy the printed `JWT_SECRET` and `ENCRYPTION_KEY` values into `.env`.

## Environment

Create this file:

```text
go-backend/.env
```

Use `.env.example` as the format:

- `PORT`
- `MONGO_URI`
- `MONGO_DB` (optional, defaults to the database in `MONGO_URI`, then `test`)
- `JWT_SECRET`
- `ENCRYPTION_KEY`
- `EMAIL_USER`
- `EMAIL_PASS`

## Routes

- `GET /`
- `POST /api/auth/register`
- `POST /api/auth/verify-otp`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/passwords`
- `GET /api/passwords`
- `DELETE /api/passwords/{id}`
