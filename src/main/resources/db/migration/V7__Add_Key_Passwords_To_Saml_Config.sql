-- V7__Add_Key_Passwords_To_Saml_Config.sql
-- Adds optional encrypted password fields for specific private key aliases in saml_configs table.

ALTER TABLE saml_configs
    ADD COLUMN sp_signing_key_password_encrypted VARCHAR(512) NULL AFTER sp_signing_key_alias,
    ADD COLUMN sp_encryption_key_password_encrypted VARCHAR(512) NULL AFTER sp_encryption_key_alias;