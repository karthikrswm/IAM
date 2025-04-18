# file: README.md
# README for the Multi-Tenant IAM Service

## Overview

This project implements a multi-tenant Identity and Access Management (IAM) service using Spring Boot. It provides core functionalities for managing organizations (tenants), users, roles, and authentication/authorization mechanisms.

## Features

* **Multi-Tenancy:** Supports multiple organizations, each with its own users and configurations.
* **User Management:** CRUD operations for users within organizations.
* **Organization Management:** CRUD operations for organizations (requires SUPER role).
* **Role-Based Access Control (RBAC):** Predefined roles (SUPER, ADMIN, USER) with authorization enforced via Spring Security.
* **Authentication:**
    * **JWT:** Username/Password based authentication issuing JSON Web Tokens.
    * **OAuth 2.0 / OIDC:** Integration with external providers (e.g., Google, Okta) via dynamic, per-organization configuration. Includes Just-In-Time (JIT) user provisioning and custom success/failure handling.
    * **SAML 2.0:** Integration with external Identity Providers (IdPs) via dynamic, per-organization configuration. Includes Just-In-Time (JIT) user provisioning via custom converter and placeholder credential handling (PKCS#12).
* **SSO Configuration:** API endpoints to manage SAML and OAuth2 settings per organization.
* **Session Management:** Uses Redis-backed HTTP sessions (via Spring Session Data Redis). Session ID resolved via `X-Auth-Token` header by default (configurable).
* **CSRF Protection:** Enabled using `CookieCsrfTokenRepository`.
* **Account Lifecycle:**
    * Email Verification (with resend option)
    * Password Reset Flow
    * Account Locking (on failed attempts)
    * Password Expiry (with pre-expiry warnings and notifications to user/admins) // <<< UPDATED
    * Inactive Account Disabling
* **Auditing:** Asynchronous and reliable audit logging of significant events to the database. Audit events are published to Kafka (Outbox Pattern) and consumed by a separate `iam-consumer` service (manual acknowledgment and DLT configured).
* **Notifications:** Email notifications for verification, password reset, account locking, password expiry warnings, password expiration events (user & admins). // <<< UPDATED
* **API Documentation:** OpenAPI (Swagger) documentation available.

## Technology Stack

* **Backend:** Java 17, Spring Boot 3.x, Spring Security 6.x, Spring Data JPA (Hibernate)
* **Database:** MySQL (managed via Flyway migrations)
* **Caching/Session:** Redis (via Spring Session Data Redis)
* **Messaging:** Apache Kafka (for Auditing)
* **Build:** Apache Maven
* **Containerization:** Docker, Docker Compose (for development infrastructure & application services)
* **Libraries:** Lombok, JJWT, Springdoc OpenAPI

## Setup & Running (Development)

### Prerequisites

* JDK 17+
* Maven 3.8+
* Docker & Docker Compose

### Configuration

1.  **Environment Variables:** Create a `.env` file in the project root directory by copying `.env.example` (if provided) or based on the `docker-compose.yml` environment section. Populate it with your local database credentials, JWT secret, Redis password (optional), **and a secure `APP_ENCRYPTION_KEY` (Base64 encoded, 256-bit AES recommended, e.g., `openssl rand -base64 32`)**. // <<< UPDATED encryption key requirement
    * Update MySQL passwords (`MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`) in `.env`.
    * If you want to use a Redis password, set `REDIS_PASSWORD` in `.env`.

2.  **Application Properties:** Review `src/main/resources/application.properties` for default settings (ports, topic names, scheduler timings, credential expiry/warning days, etc.) and override via `.env` or system properties if needed.

### Building Docker Images
*(Assuming hybrid setup: consumer in Docker, service local)*

1.  **(If Separated) Build Consumer Service JAR:**
    ```bash
    # In the iam-consumer project root (if created separately)
    # mvn clean package -DskipTests
    ```
2.  **Build Consumer Docker Image (Optional - Compose can build):**
    ```bash
    # In the iam-consumer project root (if created separately)
    # docker build -t your-dockerhub-username/iam-consumer:latest .
    ```

### Running the Infrastructure & Consumer

```bash
# Ensure .env file is present
docker-compose up -d mysql_db redis_cache kafka zookeeper mailhog kafdrop iam-consumer