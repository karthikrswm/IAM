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
    * **OAuth 2.0 / OIDC:** Integration with external providers (e.g., Google, Okta) via dynamic, per-organization configuration. Includes Just-In-Time (JIT) user provisioning.
    * **SAML 2.0:** Integration with external Identity Providers (IdPs) via dynamic, per-organization configuration. Includes Just-In-Time (JIT) user provisioning.
* **SSO Configuration:** API endpoints to manage SAML and OAuth2 settings per organization.
* **Account Lifecycle:**
    * Email Verification
    * Password Reset Flow
    * Account Locking (on failed attempts)
    * Password Expiry
    * Inactive Account Disabling
* **Auditing:** Asynchronous and reliable audit logging of significant events to the database and publishing to Kafka (Outbox Pattern).
* **Notifications:** Email notifications for verification, password reset, account locking, etc.
* **API Documentation:** OpenAPI (Swagger) documentation available.

## Technology Stack

* **Backend:** Java 17, Spring Boot 3.x, Spring Security 6.x, Spring Data JPA (Hibernate)
* **Database:** MySQL (managed via Flyway migrations)
* **Caching/Session:** Redis (via Spring Session Data Redis)
* **Messaging:** Apache Kafka (for Auditing)
* **Build:** Apache Maven
* **Containerization:** Docker, Docker Compose (for development infrastructure)
* **Libraries:** Lombok, JJWT, Springdoc OpenAPI

## Setup & Running (Development)

### Prerequisites

* JDK 17+
* Maven 3.8+
* Docker & Docker Compose

### Configuration

1.  **Environment Variables:** Create a `.env` file in the project root directory by copying `.env.example` (if provided) or based on the `docker-compose.yml` environment section. Populate it with your local database credentials, JWT secret, Redis password (optional), etc.
    * **Important:** Generate a secure JWT secret (e.g., `openssl rand -base64 32`) and update `SECURITY_JWT_SECRET` in `.env`.
    * Update MySQL passwords (`MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`) in `.env`.
    * If you want to use a Redis password, set `REDIS_PASSWORD` in `.env`.

### Running the Infrastructure

```bash
docker-compose up -d