-- V3__Add_Saml_OAuth_Config_Tables.sql
-- Adds tables for storing SAML 2.0 and OAuth 2.0 configuration per organization.
-- Using BINARY(16) for UUIDs and MySQL 5+ compatible TIMESTAMPs.

-- Create SAML Configs Table
CREATE TABLE saml_configs (
                              id                            BINARY(16)    NOT NULL PRIMARY KEY,
                              organization_id               BINARY(16)    NOT NULL UNIQUE,
                              idp_metadata_url              VARCHAR(1024),
                              sp_entity_id                  VARCHAR(255)  NOT NULL,
                              sp_acs_url                    VARCHAR(1024) NOT NULL,
                              sp_slo_url                    VARCHAR(1024),
                              name_id_format                VARCHAR(100)  DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                              sign_requests                 BOOLEAN       NOT NULL DEFAULT FALSE,
                              want_assertions_signed        BOOLEAN       NOT NULL DEFAULT TRUE,
                              sp_signing_certificate        TEXT,
                              sp_encryption_certificate     TEXT,
                              idp_signing_certificate       TEXT,
                              attr_map_username             VARCHAR(100)  DEFAULT 'uid',
                              attr_map_email                VARCHAR(100)  DEFAULT 'mail',
                              attr_map_roles                VARCHAR(100),
                              enabled                       BOOLEAN       NOT NULL DEFAULT FALSE,
                              created_by                    VARCHAR(50),
                              created_date                  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                              last_modified_by              VARCHAR(50),
                              last_modified_date            TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                              CONSTRAINT fk_saml_config_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_saml_config_sp_entity_id ON saml_configs(sp_entity_id);


-- Create OAuth2 Configs Table
CREATE TABLE oauth2_configs (
                                id                            BINARY(16)    NOT NULL PRIMARY KEY,
                                organization_id               BINARY(16)    NOT NULL UNIQUE,
                                provider                      VARCHAR(50)   NOT NULL,
                                client_id                     VARCHAR(255)  NOT NULL,
                                client_secret                 VARCHAR(512)  NOT NULL,
                                authorization_uri             VARCHAR(1024),
                                token_uri                     VARCHAR(1024),
                                user_info_uri                 VARCHAR(1024),
                                jwk_set_uri                   VARCHAR(1024),
                                redirect_uri_template         VARCHAR(1024),
                                scopes                        VARCHAR(512)  DEFAULT 'openid,profile,email',
                                user_name_attribute_name      VARCHAR(100)  DEFAULT 'sub',
                                user_email_attribute_name     VARCHAR(100)  DEFAULT 'email',
                                enabled                       BOOLEAN       NOT NULL DEFAULT FALSE,
                                created_by                    VARCHAR(50),
                                created_date                  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                last_modified_by              VARCHAR(50),
                                last_modified_date            TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                CONSTRAINT fk_oauth2_config_organization FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_oauth2_config_provider ON oauth2_configs(provider);