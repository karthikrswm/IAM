-- V8__Add_Manual_IdP_Fields_To_Saml_Config.sql
-- Adds optional columns to saml_configs for manual IdP configuration fallback.

ALTER TABLE saml_configs
    ADD COLUMN idp_entity_id VARCHAR(255) NULL AFTER want_assertions_signed,
    ADD COLUMN idp_sso_url VARCHAR(1024) NULL AFTER idp_entity_id,
    ADD COLUMN idp_sso_binding ENUM('POST', 'REDIRECT') NULL AFTER idp_sso_url; -- Stores enum name: POST or REDIRECT

-- Optionally add index if querying by IdP entity ID becomes common
-- CREATE INDEX idx_saml_config_idp_entity_id ON saml_configs(idp_entity_id);