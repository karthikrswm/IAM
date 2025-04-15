-- V2__Add_User_Account_Status.sql
-- Adds columns related to user account status, login tracking, and password management to the 'users' table.
-- Using BINARY(16) for UUID variable. Includes collation fix.

-- Set connection collation to match table default to avoid mix errors in WHERE clause
SET collation_connection = 'utf8mb4_unicode_ci';

-- Add new status and tracking columns to the 'users' table
ALTER TABLE users
    ADD COLUMN account_non_expired     BOOLEAN   NOT NULL DEFAULT TRUE AFTER organization_id,
    ADD COLUMN account_non_locked      BOOLEAN   NOT NULL DEFAULT TRUE AFTER account_non_expired,
    ADD COLUMN credentials_non_expired BOOLEAN   NOT NULL DEFAULT TRUE AFTER account_non_locked,
    ADD COLUMN enabled                 BOOLEAN   NOT NULL DEFAULT FALSE AFTER credentials_non_expired,
    ADD COLUMN failed_login_attempts INT       NOT NULL DEFAULT 0 AFTER enabled,
    ADD COLUMN lock_time               TIMESTAMP NULL     DEFAULT NULL AFTER failed_login_attempts,
    ADD COLUMN password_changed_date   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER lock_time,
    ADD COLUMN last_login_date         TIMESTAMP NULL     DEFAULT NULL AFTER password_changed_date,
    ADD COLUMN temporary_password      BOOLEAN   NOT NULL DEFAULT TRUE AFTER last_login_date;

-- Add Indexes for scheduler queries on new status columns
CREATE INDEX idx_user_lock_status_time ON users (account_non_locked, lock_time);
CREATE INDEX idx_user_cred_status_pwd_change ON users (credentials_non_expired, password_changed_date);
CREATE INDEX idx_user_enabled_last_login ON users (enabled, last_login_date);


-- Update existing users based on V1 seed data assumptions
SET @super_user1_id = UUID_TO_BIN('e0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13'); -- Use BIN function to match V1 SET type

UPDATE users SET
                 enabled = TRUE,
                 temporary_password = FALSE,
                 credentials_non_expired = TRUE,
                 account_non_expired = TRUE,
                 account_non_locked = TRUE,
                 password_changed_date = created_date
WHERE id = @super_user1_id; -- Comparison uses connection collation set above