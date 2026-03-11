# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Multi-tenant Identity and Access Management (IAM) service built with Spring Boot 3.2.5 and Java 21 (with `--enable-preview`). Supports JWT, OAuth2/OIDC, and SAML 2.0 authentication with per-organization SSO configuration stored in the database.

## Build & Run Commands

```bash
# Build (skip tests since there are none yet)
./mvnw clean package -DskipTests

# Run locally (requires infrastructure via Docker)
./mvnw spring-boot:run

# Start infrastructure services (MySQL, Redis, Kafka, MailHog, Kafdrop)
docker-compose up -d mysql_db redis_cache kafka zookeeper mailhog kafdrop
```

### Required Environment Variables

Set these in `.env` or IDE run configuration:
- `MYSQL_PASSWORD` - MySQL database password
- `SECURITY_JWT_SECRET` - JWT signing secret
- `APP_ENCRYPTION_KEY` - Base64-encoded 256-bit AES key (for encrypting SSO credentials)
- `REDIS_PASSWORD` - Redis password (optional)

## Architecture

### Multi-Tenancy Model

Organization is the tenant boundary. Users, roles, and SSO configurations (OAuth2/SAML) are scoped per organization. Three roles: `SUPER` (cross-org), `ADMIN` (org-scoped), `USER`.

### Authentication Flows

- **JWT**: `AuthController` → `AuthService` → `AuthenticationManager` → `JwtUtils`. JWT filter (`JwtAuthenticationFilter`) validates tokens on subsequent requests.
- **OAuth2**: Dynamic client registrations loaded from DB via `DatabaseClientRegistrationRepository`. JIT user provisioning in `CustomOAuth2UserService`. Custom success/failure handlers redirect after auth.
- **SAML 2.0**: Dynamic relying party registrations from DB via `DatabaseRelyingPartyRegistrationRepository`. JIT provisioning via `CustomSaml2AuthenticationConverter` → `CustomSaml2UserService`. Credentials (PKCS#12) managed by `CredentialService`/`FileSystemCredentialService`.

### SSO Configuration

`ConfigController`/`ConfigService` manage per-org OAuth2 and SAML settings. Client secrets and SAML key passwords are encrypted via `AesGcmEncryptionService` (AES-GCM) before database storage.

### Session & Security

- Redis-backed sessions via Spring Session (`X-Auth-Token` header)
- CSRF protection with `CookieCsrfTokenRepository` (cookie name: `XSRF-TOKEN`)
- `SecurityConfig` defines two filter chains and all security beans

### Audit & Messaging

Audit events are persisted to the database, then published to Kafka (`iam-audit-events` topic) via an outbox pattern scheduler (`AuditEventScheduler`). A separate `iam-consumer` service (in `../iam-consumer`) processes events from Kafka.

### Account Lifecycle

Scheduled jobs handle: account unlock, credential expiry/warnings, inactive account disabling, and token cleanup. Cron expressions configured in `application.properties` under `iam.scheduler.*`.

### Database Migrations

Flyway manages schema migrations in `src/main/resources/db/migration/`. Convention: `V{N}__{Description}.sql`. Hibernate is set to `validate` mode — all schema changes must go through Flyway.

## Key Conventions

- **Lombok**: All entities and services use `@RequiredArgsConstructor`, `@Builder`, `@Slf4j`, etc.
- **DTOs**: Request/response DTOs in `dto/` package, validated with Jakarta Bean Validation annotations
- **Error handling**: `GlobalExceptionHandler` maps custom exceptions (`BadRequestException`, `ConflictException`, `ResourceNotFoundException`, etc.) to `ApiError` responses
- **Constants**: API error/response messages centralized in `constant/ApiErrorMessages` and `constant/ApiResponseMessages`
- **Async**: Email notifications sent asynchronously via `@Async` with custom executor (`AsyncConfig`)