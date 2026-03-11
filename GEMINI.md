# GEMINI.md - IAM Service

## Project Overview
The **IAM Service** is a multi-tenant Identity and Access Management (IAM) system built using **Spring Boot 3.2.5** and **Java 21**. It provides core functionalities for managing organizations (tenants), users, roles, and a wide array of authentication/authorization mechanisms.

### Key Features
- **Multi-Tenancy:** Each organization has its own users and SSO configurations.
- **Authentication:** Supports **JWT** (Username/Password), **OAuth 2.0 / OIDC** (dynamic per-org), and **SAML 2.0** (dynamic per-org with JIT provisioning).
- **Session Management:** Redis-backed HTTP sessions via Spring Session Data Redis, using the `X-Auth-Token` header.
- **RBAC:** Roles including `SUPER`, `ADMIN`, and `USER`.
- **Auditing:** Asynchronous audit logging using the **Outbox Pattern** with **Kafka**.
- **Account Lifecycle:** Email verification, password reset, account locking, and inactivity management.
- **Security:** CSRF protection (`CookieCsrfTokenRepository`), AES-GCM encryption for sensitive configurations, and BCrypt password hashing.

### Technology Stack
- **Backend:** Java 21 (with preview features), Spring Boot 3.x, Spring Security 6.x, Spring Data JPA (Hibernate).
- **Database:** MySQL (managed via Flyway migrations).
- **Caching/Session:** Redis.
- **Messaging:** Apache Kafka.
- **Documentation:** Springdoc OpenAPI (Swagger).
- **Build/Containerization:** Maven, Docker, Docker Compose.

---

## Building and Running

### Prerequisites
- **JDK 21** (Maven is configured with `--enable-preview`).
- **Maven 3.8+**.
- **Docker & Docker Compose**.

### Environment Setup
Create a `.env` file or set the following environment variables:
- `MYSQL_PASSWORD`: Password for the `iam_user` database user.
- `SECURITY_JWT_SECRET`: Secret key for signing JWTs.
- `APP_ENCRYPTION_KEY`: Base64 encoded 256-bit AES key for config encryption.
- `REDIS_PASSWORD`: (Optional) If Redis requires authentication.

### Commands
- **Build:** `mvn clean package`
- **Infrastructure (Docker):** `docker-compose up -d mysql_db redis_cache kafka zookeeper mailhog kafdrop iam-consumer`
- **Run Application:** `java --enable-preview -jar target/iam-1.0.0-SNAPSHOT.jar` (or run `IamApplication` from your IDE).
- **Test:** `mvn test`

### API Documentation
Once running, Swagger UI is available at: `http://localhost:8080/swagger-ui.html`

---

## Development Conventions

### Architecture & Patterns
- **Layered Architecture:** Follows the `Controller -> Service -> Repository` pattern.
- **Transactional Services:** Business logic and authorization checks reside in the `@Service` layer.
- **Consistent Responses:** Use `ApiSuccessResponse<T>` for successful API calls and `ApiError` for failures.
- **Security Context:** Use `SecurityUtils` to access the currently authenticated user's details (username, orgId, roles).
- **Auditing:** Log significant events via `AuditEventService`, which handles database persistence and Kafka publishing.

### Coding Style
- **Lombok:** Use `@Data`, `@Getter`, `@Setter`, `@RequiredArgsConstructor`, and `@Slf4j` to reduce boilerplate.
- **Validation:** Use Jakarta Validation annotations (e.g., `@Valid`, `@NotBlank`, `@Email`) in DTOs.
- **Authorization:** Prefer method-level security using `@PreAuthorize` (e.g., `@PreAuthorize("hasRole('ADMIN')")`).
- **Naming:** Follow standard Spring/Java conventions. Databases use standard physical naming (snake_case columns).
- **Logging:** Use SLF4J with descriptive messages. Log actor information for sensitive operations.

### Configuration
- **SSO:** OAuth2 and SAML configurations are stored in the database (`Oauth2Config`, `SamlConfig`) to support dynamic multi-tenancy.
- **Encryption:** Sensitive fields like `client_secret` or private keys are encrypted using `AesGcmEncryptionService`.
