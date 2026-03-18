# 🔐 AuthService

AuthService is a Spring Boot microservice responsible for issuing, validating, refreshing, and revoking JWT tokens.

It is designed to be used within a microservice architecture, where other services rely on it for authentication.

---

## 🚀 Features

* Issue access & refresh tokens
* Validate JWT tokens
* Refresh token pairs
* Blacklist (revoke) refresh tokens
* Stateless authentication

---

## 🏗️ Tech Stack

* Java
* Spring Boot
* Spring Security
* JWT

---

## 🔑 API Endpoints

Base path: `/api/v1/auth`

| Method | Endpoint     | Description                              |
| ------ | ------------ | ---------------------------------------- |
| POST   | `/issue`     | Issue access + refresh tokens (internal) |
| POST   | `/validate`  | Validate access token                    |
| POST   | `/refresh`   | Generate new token pair                  |
| POST   | `/blacklist` | Revoke (blacklist) refresh token         |

---

## 📥 Request Examples

### Issue (Internal)

```json
{
  "userId": "123",
  "username": "user",
  "roles": ["USER"]
}
```

### Validate

```json
{
  "token": "access-token"
}
```

### Refresh

```json
{
  "refreshToken": "refresh-token"
}
```

### Blacklist

```json
{
  "token": "refresh-token",
  "reason": "logout"
}
```

---

## 📤 Response Example

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "tokenType": "Bearer",
  "accessExpiresIn": 900,
  "refreshExpiresIn": 2592000
}
```

---

## 🔒 Security Notes

* `/issue` requires an internal API key
* `/blacklist` requires a valid Bearer access token
* `/validate` and `/refresh` are public
* Refresh tokens can be invalidated via blacklist

---

## ▶️ Running the Project

```bash
git clone https://github.com/Laacho/AuthService.git
cd AuthService
./mvnw spring-boot:run
```
