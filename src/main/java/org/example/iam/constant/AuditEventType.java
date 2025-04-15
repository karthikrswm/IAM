// File: src/main/java/org/example/iam/constant/AuditEventType.java
package org.example.iam.constant;

import lombok.Getter;

/**
 * Defines the types of audit events recorded in the system. Provides a standardized way to
 * categorize logged actions, enhancing audit trail readability and analysis.
 * <p>
 * Each enum constant represents a distinct action or system event that should be logged
 * for security, compliance, or operational monitoring purposes.
 * </p>
 */
@Getter // Lombok annotation automatically generates getter for the 'description' field.
public enum AuditEventType {

    // --- Authentication Events ---
    LOGIN_SUCCESS("Login successful"),
    LOGIN_FAILURE("Login failed"), // Details should specify reason (bad_credentials, locked, etc.)
    LOGOUT_SUCCESS("Logout successful"), // Track explicit logouts
    PASSWORD_RESET_REQUESTED("Password reset requested"),
    PASSWORD_RESET_SUCCESS("Password reset successful"),
    PASSWORD_RESET_FAILURE("Password reset failed"),
    PASSWORD_UPDATED("Password updated by user"), // User changing own password
    ADMIN_PASSWORD_RESET("Admin reset user password"), // Admin initiated password reset
    TOKEN_INVALIDATED("Authentication token invalidated"), // e.g., explicit logout with token invalidation

    // --- User Management Events ---
    USER_CREATED("User created"),
    USER_UPDATED("User profile updated"), // Changes to non-critical fields (phone, secondary email)
    USER_CRITICAL_UPDATED("User critical info updated"), // Changes to primary email, username (if allowed)
    USER_DELETED("User deleted"),
    USER_ENABLED("User account enabled"), // Often after email verification
    USER_DISABLED("User account disabled"), // Admin or system action (e.g., inactivity)
    ROLE_ASSIGNED("Role assigned to user"),
    ROLE_REMOVED("Role removed from user"),

    // --- Organization Management Events ---
    ORGANIZATION_CREATED("Organization created"),
    ORGANIZATION_UPDATED("Organization updated"), // Changes to name, login type, etc.
    ORGANIZATION_DELETED("Organization deleted"),
    ORG_CONFIG_UPDATED("Organization configuration updated"), // SAML/OAuth2 config changes

    // --- Security & Account Status Events ---
    ACCOUNT_LOCKED("User account locked"), // Due to failed login attempts
    ACCOUNT_UNLOCKED("User account unlocked"), // Manual admin action or automatic scheduler unlock
    CREDENTIALS_EXPIRED("User credentials expired"), // Marked by scheduler based on password age
    ACCOUNT_INACTIVITY_DISABLED("User account disabled due to inactivity"), // Automatic scheduler action

    // --- Token/Verification Events ---
    VERIFICATION_EMAIL_SENT("Verification email sent"),
    EMAIL_VERIFIED("Email address verified"), // Successful use of verification token
    VERIFICATION_TOKEN_USED("Verification token used"), // Generic event for token usage attempt
    PASSWORD_RESET_EMAIL_SENT("Password reset email sent"),
    PASSWORD_RESET_TOKEN_USED("Password reset token used"), // Successful password reset via token
    TOKEN_VALIDATION_SUCCESS("Token validation successful"), // e.g., JWT validation success
    TOKEN_VALIDATION_FAILURE("Token validation failed"), // e.g., JWT expired, invalid signature, incorrect type

    // --- System Events ---
    SYSTEM_ERROR("System error occurred"), // Catch-all for unexpected errors needing investigation
    SCHEDULER_JOB_STARTED("Scheduler job started"), // e.g., Account status check job
    SCHEDULER_JOB_COMPLETED("Scheduler job completed"); // e.g., Account status check job

    /**
     * A brief, human-readable description of the audit event type.
     */
    private final String description;

    /**
     * Constructor for the enum constant.
     *
     * @param description A human-readable default description for this event type.
     */
    AuditEventType(String description) {
        this.description = description;
    }

    // No additional methods currently needed for this enum.
}