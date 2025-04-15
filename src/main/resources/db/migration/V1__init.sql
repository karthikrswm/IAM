-- V1__init.sql
-- Initial schema setup and seeding for IAM Service
-- FINAL VERSION: Using BINARY(16) for UUIDs, App-level UUID generation, MySQL 5+ compatible Timestamps.

-- Create Organizations Table
CREATE TABLE organizations
(
    id                 BINARY(16)   NOT NULL PRIMARY KEY,
    org_name           VARCHAR(100) NOT NULL,
    org_domain         VARCHAR(100) NOT NULL,
    login_type         ENUM('JWT', 'SAML', 'OAUTH2') NOT NULL DEFAULT 'JWT',
    is_super_org       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_by         VARCHAR(50),
    created_date       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_by   VARCHAR(50),
    last_modified_date TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_org_name (org_name),
    UNIQUE KEY uk_org_domain (org_domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create Roles Table
CREATE TABLE roles
(
    id                 BINARY(16)  NOT NULL PRIMARY KEY,
    role_type          ENUM('SUPER', 'ADMIN', 'USER') NOT NULL,
    created_by         VARCHAR(50),
    created_date       TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_by   VARCHAR(50),
    last_modified_date TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_role_type (role_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Create Users Table
CREATE TABLE users
(
    id                 BINARY(16)   NOT NULL PRIMARY KEY,
    username           VARCHAR(50)  NOT NULL,
    password           VARCHAR(100) NOT NULL,
    primary_email      VARCHAR(100) NOT NULL,
    secondary_email    VARCHAR(100),
    phone_number       VARCHAR(20),
    organization_id    BINARY(16)   NOT NULL,
    created_by         VARCHAR(50),
    created_date       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_by   VARCHAR(50),
    last_modified_date TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_username (username),
    UNIQUE KEY uk_user_primary_email (primary_email),
    CONSTRAINT fk_user_organization FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create User Roles Join Table
CREATE TABLE user_roles
(
    user_id BINARY(16) NOT NULL,
    role_id BINARY(16) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create Audit Events Table
CREATE TABLE audit_events
(
    id                    BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id              BINARY(16)    NOT NULL UNIQUE, -- App generates UUID
    event_type            VARCHAR(50)   NOT NULL,
    description           TEXT,
    actor                 VARCHAR(50),
    target_resource_type  VARCHAR(50),
    target_resource_id    VARCHAR(50),
    organization_id       BINARY(16),
    event_timestamp       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status                VARCHAR(10)   NOT NULL DEFAULT 'SUCCESS',
    details               TEXT,
    INDEX idx_audit_event_type (event_type),
    INDEX idx_audit_event_timestamp (event_timestamp),
    INDEX idx_audit_actor (actor),
    INDEX idx_audit_target_resource (target_resource_type, target_resource_id),
    INDEX idx_audit_organization_id (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create Verification Tokens Table
CREATE TABLE verification_tokens
(
    id                  BINARY(16)   NOT NULL PRIMARY KEY, -- App generates UUID (or Hibernate)
    token               VARCHAR(100) NOT NULL,
    user_id             BINARY(16)   NOT NULL,
    token_type          ENUM('EMAIL_VERIFICATION','PASSWORD_RESET')  NOT NULL,
    expiry_date         TIMESTAMP    NOT NULL,
    created_by          VARCHAR(50),
    created_date        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_by    VARCHAR(50),
    last_modified_date  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_verification_token (token),
    INDEX idx_verification_user_type (user_id, token_type),
    INDEX idx_verification_expiry_date (expiry_date),
    CONSTRAINT fk_token_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- --- SEED INITIAL DATA ---

-- Define fixed UUIDs using UUID_TO_BIN for variable assignment
SET @super_org_id   = UUID_TO_BIN('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11');
SET @super_role_id  = UUID_TO_BIN('f0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12');
SET @admin_role_id  = UUID_TO_BIN('c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a15');
SET @user_role_id   = UUID_TO_BIN('b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a16');
SET @super_user1_id = UUID_TO_BIN('e0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13');

-- BCrypt hash for the password "password"
SET @default_password_hash = '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.AQubh4a';

-- System user for auditing initial seed
SET @system_auditor = 'FLYWAY_SEED';

-- Insert Super Organization
INSERT INTO organizations (id, org_name, org_domain, login_type, is_super_org, created_by, last_modified_by)
VALUES (@super_org_id, 'Super Organization', 'super.com', 'JWT', TRUE, @system_auditor, @system_auditor);

-- Insert Standard Roles
INSERT INTO roles (id, role_type, created_by, last_modified_by)
VALUES (@super_role_id, 'SUPER', @system_auditor, @system_auditor),
       (@admin_role_id, 'ADMIN', @system_auditor, @system_auditor),
       (@user_role_id,  'USER',  @system_auditor, @system_auditor);

-- Insert Initial Super User
INSERT INTO users (id, username, password, primary_email, organization_id, created_by, last_modified_by)
VALUES (@super_user1_id, 'superuser1', @default_password_hash, 'superuser1@super.com', @super_org_id, @system_auditor, @system_auditor);

-- Assign SUPER role to the initial Super User
INSERT INTO user_roles (user_id, role_id)
VALUES (@super_user1_id, @super_role_id);