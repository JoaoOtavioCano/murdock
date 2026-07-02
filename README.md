# Murdock

![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat&logo=go)
![Architecture](https://img.shields.io/badge/Architecture-Hexagonal-ff69b4?style=flat)
![Database](https://img.shields.io/badge/PostgreSQL-316192?style=flat&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=flat&logo=docker&logoColor=white)

**Murdock** is a lightweight, highly secure, and modular authentication and authorization backend service built in Go. Designed from the ground up utilizing **Hexagonal Architecture (Ports and Adapters)**, Murdock demonstrates clean domain boundaries, robust cryptographic practices, and dependency-free HTTP routing powered purely by the Go standard library.

---

## 📋 Table of Contents
- [Overview & Architecture](#overview--architecture)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Configuration](#environment-configuration)
  - [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
  - [Authentication Flow](#authentication-flow)
  - [Endpoints Reference](#endpoints-reference)
- [Testing](#testing)

---

## 🏛 Architecture Overview

Murdock enforces strict separation of concerns through **Ports and Adapters (Hexagonal Architecture)**:

- **Core Application Layer (`application/`)**: Encapsulates all business logic, user models, password hashing, ID generation (UUID v7), and session validation. It remains completely agnostic of transport protocols or database implementations.
- **Inbound Ports (`ports/inbound/`)**: Define the contracts and commands (e.g., `LoginCmd`, `SignupCmd`) through which external consumers interact with the core domain.
- **Outbound Ports (`ports/outbound/`)**: Define interfaces for data persistence (`Database`), notifications (`NotificationPort`), and security blocklists (`PasswordBlockListPort`).
- **Adapters (`adapters/`)**: Implement the outbound ports (PostgreSQL storage, Have I Been Pwned API client, email services) and drive the inbound ports (`net/http` API server).

---

## ✨ Key Features

### 🔐 Zero-Bloat & Standard Library First
- **Native Routing**: Leveraging Go 1.22+ enhanced `http.ServeMux` for declarative HTTP routing (`POST /v1/sessions`, `DELETE /v1/users`) without heavy third-party web frameworks.
- **Custom Cryptography Suite**: Built-in implementation of JSON Web Token (JWT) issuance, HMAC-SHA256 signing, and base64url decoding tailored to exact security specs.

### 🛡 Enterprise-Grade Defense Mechanisms
- **PBKDF2-HMAC-SHA256 Hashing**: Passwords are protected using per-user unique random salts and an application-wide secret **pepper**, hardened with high-iteration PBKDF2 derivation.
- **Proactive Password Blocklist**: Automatically queries the **Have I Been Pwned (k-Anonymity API)** during signup and password changes to block compromised or weak credentials.
- **Brute-Force & Login Throttling**: Tracks consecutive authentication failures in PostgreSQL (`LoginThrottler`) and temporarily locks user accounts exceeding maximum threshold attempts.
- **Secure Cookie Storage**: Authenticated sessions deliver JWTs inside hardened HTTP cookies (`HttpOnly: true`, `Secure: true`, `SameSite: Lax`).

### 📩 Complete Identity Lifecycle
- Account creation with email confirmation code validation.
- Secure, tokenized password recovery and change requests.
- Account status transitions (`pending`, `active`, `locked`).
- Transactional account deletion (`DELETE /v1/users`) with automated rollback protections.

---

## 📂 Project Structure

```text
murdock/
├── adapters/
│   ├── blocklistapi/       # Have I Been Pwned API integration
│   ├── database/postgres/  # PostgreSQL transactional database adapter
│   ├── emailsender/        # Email notification adapter & HTML templates
│   └── httpAdapter/        # HTTP server entrypoint and route handlers
├── application/
│   ├── models/             # Domain models (User, Session, ConfirmationCode)
│   ├── auth_service.go     # Core authentication orchestrator
│   ├── authentication.go   # PBKDF2 hashing and JWT token management
│   └── login_throttler.go  # Rate limiting and account lock mechanism
├── ports/
│   ├── errors/             # Domain-specific custom errors
│   ├── inbound/            # Application commands & inbound handler interfaces
│   └── outbound/           # Database, Notification, and Blocklist interfaces
├── migrations/             # SQL database initialization scripts
├── compose.yml             # Docker Compose configuration for local dev
├── Dockerfile              # Multi-stage production container build
└── main.go                 # Application bootstrap and dependency injection
```

---

## 🚀 Getting Started

### Prerequisites

* **Go**: Version `1.24.0` or higher
* **PostgreSQL**: Version `15+`
* **Docker & Docker Compose**: (Optional, for containerized execution)

### Environment Configuration

Create a `.env` file in the project root directory:

```env
# Server Configuration
HOST=0.0.0.0
PORT=8080

# Security Secrets
PEPPER=super_secret_global_pepper_string_32_bytes
JWT_SECRET=your_jwt_hmac_signing_secret_key

# PostgreSQL Database
DB_USER=postgres
DB_PASSWORD=secretpassword
DB_NAME=murdock_db
DB_HOST=localhost
DB_SSL_MODE=disable
```

### Running the Application

#### Option 1: Using Docker Compose (Recommended)

This command initializes the Murdock backend service alongside a persistent PostgreSQL database container:

```bash
make compose_up
```

#### Option 2: Running Locally via Go CLI

Ensure your local PostgreSQL instance is active and configured according to your `.env` settings:

```bash
# Install dependencies
go mod tidy

# Run the backend server
make run
```

---

## 📡 API Documentation

All HTTP requests and responses communicate via `Content-Type: application/json`.

### Endpoints Reference

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| `POST` | `/v1/users` | Register a new user account (returns `201 Created`). | No |
| `POST` | `/v1/verifications` | Verify email OTP code to activate account. | No |
| `POST` | `/v1/sessions` | Authenticate credentials & receive `murdock_token` cookie. | No |
| `POST` | `/v1/sessions/status` | Verify token signature & check session expiration. | Yes |
| `POST` | `/v1/password-resets` | Request password reset OTP code sent to email. | No |
| `DELETE` | `/v1/users` | Permanently purge authenticated user account. | Yes |

---

### Request & Response Payload Examples

#### 1. User Registration (`POST /v1/users`)

Creates a user in `pending` status and triggers a verification email.

**Request:**

```json
{
  "method": "EmailPasswordMethod",
  "data": {
    "email": "developer@example.com",
    "password": "CorrectHorseBatteryStaple2026!"
  }
}
```

#### 2. Confirm Email Code (`POST /v1/verifications`)

Activates a `pending` account using the 6-digit verification code.

**Request:**

```json
{
  "digitalAddr": "developer@example.com",
  "code": "849201"
}
```

#### 3. Sign In (`POST /v1/sessions`)

Validates credentials against PBKDF2 hash. If successful, sets an HTTP-Only cookie and injects the JWT into the response header.

**Request:**

```json
{
  "method": "EmailPasswordMethod",
  "data": {
    "email": "developer@example.com",
    "password": "CorrectHorseBatteryStaple2026!"
  }
}
```

**Response Headers:**

```http
HTTP/1.1 200 OK
Set-Cookie: murdock_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Lax
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 4. Validate Session (`POST /v1/sessions/status`)

Verifies active JWT token integrity. Returns `204 No Content` if valid.

**Request:**

```json
{
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

---

## 🧪 Testing

Murdock comes equipped with a comprehensive suite of unit and adapter integration tests covering core cryptography, confirmation codes, blocklist validation, and service orchestration.

To run all tests across packages:

```bash
make test
```