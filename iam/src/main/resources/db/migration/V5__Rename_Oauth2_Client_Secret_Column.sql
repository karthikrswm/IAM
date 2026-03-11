-- V5__Rename_Oauth2_Client_Secret_Column.sql
-- Renames the client_secret column to match the updated Oauth2Config entity field name.

ALTER TABLE oauth2_configs
    CHANGE COLUMN client_secret client_secret_encrypted VARCHAR(512) NOT NULL;

-- Renames the idp_signing_certificate column to match the updated SamlConfig entity field name.

ALTER TABLE saml_configs
    CHANGE COLUMN idp_signing_certificate idp_verification_certificate_pem TEXT;
-- Assuming the original type was TEXT, adjust if it was different in your V3.

-- V7__Add_Keystore_Fields_To_Saml_Configs.sql
-- Adds columns needed for PKCS12 keystore configuration to the saml_configs table.

ALTER TABLE saml_configs
    ADD COLUMN sp_signing_keystore_path VARCHAR(255) NULL AFTER want_assertions_signed,
    ADD COLUMN sp_signing_keystore_password_encrypted VARCHAR(512) NULL AFTER sp_signing_keystore_path,
    ADD COLUMN sp_signing_key_alias VARCHAR(100) NULL AFTER sp_signing_keystore_password_encrypted,
    ADD COLUMN sp_encryption_keystore_path VARCHAR(255) NULL AFTER sp_signing_key_alias,
    ADD COLUMN sp_encryption_keystore_password_encrypted VARCHAR(512) NULL AFTER sp_encryption_keystore_path,
    ADD COLUMN sp_encryption_key_alias VARCHAR(100) NULL AFTER sp_encryption_keystore_password_encrypted;

-- Note: We already renamed the idp_signing_certificate column to idp_verification_certificate_pem in V5.
-- No further changes needed for that specific column here.