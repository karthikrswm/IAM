// File: src/main/java/org/example/iam/constant/ApiErrorMessages.java
package org.example.iam.constant;

/**
 * Defines standardized error messages used across the API, particularly in error responses
 * ({@link org.example.iam.api.ApiError}) and exception messages.
 * <p>
 * Using constants ensures consistency in error reporting to clients and aids in maintainability.
 * </p>
 * This class is final and cannot be instantiated.
 */
public final class ApiErrorMessages {

  // --- Authentication & Authorization ---
  public static final String AUTHENTICATION_FAILED = "Authentication failed. Please check your credentials or account status.";
  public static final String BAD_CREDENTIALS = "Invalid username/email or password provided.";
  public static final String ACCOUNT_LOCKED = "Your account is temporarily locked due to too many failed login attempts. Please try again later or contact support.";
  public static final String ACCOUNT_DISABLED = "Your account is disabled. Please verify your email or contact support.";
  public static final String ACCOUNT_EXPIRED = "Your account has expired. Please contact support."; // Less common, might be policy-driven
  public static final String CREDENTIALS_EXPIRED = "Your password has expired. Please reset it to continue.";
  public static final String TEMPORARY_PASSWORD_REQUIRES_RESET = "Login failed. You must change your temporary password before proceeding.";
  public static final String ACCESS_DENIED = "Access Denied. You do not have the necessary permissions to perform this action or access this resource.";
  public static final String INVALID_JWT = "Invalid, expired, or malformed authentication token provided.";
  public static final String MISSING_JWT = "Authentication token is missing from the request header.";

  // --- Verification & Tokens ---
  public static final String VERIFICATION_TOKEN_INVALID = "The provided verification token is invalid or was not found.";
  public static final String VERIFICATION_TOKEN_EXPIRED = "The verification token has expired. Please request a new verification email.";
  public static final String PASSWORD_RESET_TOKEN_INVALID = "The provided password reset token is invalid or was not found.";
  public static final String PASSWORD_RESET_TOKEN_EXPIRED = "The password reset token has expired. Please request a new password reset.";
  public static final String USER_ALREADY_ENABLED = "This user account is already verified and enabled.";

  // --- Resource Not Found ---
  public static final String USER_NOT_FOUND_ID = "User not found with ID: %s"; // Use String.format()
  public static final String USER_NOT_FOUND_USERNAME = "User not found with username or email: %s"; // Use String.format()
  public static final String ORGANIZATION_NOT_FOUND_ID = "Organization not found with ID: %s"; // Use String.format()
  public static final String ORGANIZATION_NOT_FOUND_DOMAIN = "Organization not found with domain: %s"; // Use String.format()
  public static final String ROLE_NOT_FOUND = "Required role not found in the system: %s"; // Use String.format()
  public static final String RESOURCE_NOT_FOUND = "The requested resource could not be found."; // Generic fallback

  // --- Conflicts & Duplicates ---
  public static final String USERNAME_ALREADY_EXISTS = "The username '%s' is already registered. Please choose a different one."; // Use String.format()
  public static final String EMAIL_ALREADY_EXISTS = "The primary email address '%s' is already registered."; // Use String.format()
  public static final String ORG_NAME_ALREADY_EXISTS = "An organization with the name '%s' already exists."; // Use String.format()
  public static final String ORG_DOMAIN_ALREADY_EXISTS = "An organization with the domain '%s' is already registered."; // Use String.format()

  // --- Validation Errors ---
  public static final String VALIDATION_FAILED = "Validation failed. Please check the request data for errors.";
  public static final String INVALID_EMAIL_DOMAIN = "The primary email address domain must match the organization's registered domain ('%s')."; // Use String.format()
  public static final String INVALID_SECONDARY_EMAIL_DOMAIN = "The secondary email address domain ('%s') belongs to another registered organization and cannot be used."; // Use String.format()
  public static final String INVALID_DOMAIN_FORMAT = "Invalid domain name format provided.";
  public static final String INVALID_INPUT = "Invalid input provided. Please check your request data structure and values."; // General validation fallback
  public static final String PASSWORD_MISMATCH = "The new password and confirmation password do not match.";
  public static final String INVALID_PASSWORD_FORMAT = "Password does not meet the required complexity requirements."; // Add details in implementation if possible
  public static final String INVALID_ROLE_ASSIGNMENT = "Invalid role assignment attempted."; // Specific role assignment issue

  // --- Operational Errors ---
  public static final String CANNOT_DELETE_SUPER_ORG = "The Super Organization cannot be deleted.";
  public static final String CANNOT_MODIFY_SUPER_ORG = "Core properties of the Super Organization cannot be modified via this operation.";
  public static final String CANNOT_MODIFY_SUPER_ORG_LOGIN = "The login type for the Super Organization cannot be changed.";
  public static final String CANNOT_DELETE_SELF = "Users cannot delete their own account.";
  public static final String CANNOT_DISABLE_SELF = "Users cannot disable their own account.";
  public static final String CANNOT_DELETE_SUPER_USER = "Super users cannot be deleted via the API.";
  public static final String OPERATION_NOT_ALLOWED = "This operation is not permitted based on application rules or the state of the target resource.";
  public static final String EMAIL_SEND_FAILURE = "Failed to send email notification. Please try again later or contact support if the issue persists.";
  public static final String KAFKA_SEND_FAILURE = "Failed to publish event to the event stream. The operation succeeded, but auditing may be delayed.";

  // --- General Errors ---
  public static final String GENERAL_ERROR = "An unexpected internal error occurred. Please try again later or contact support if the issue persists."; // Generic fallback for 500
  public static final String DATABASE_ERROR = "A database error occurred while processing the request."; // More specific internal error
  public static final String CONFIGURATION_ERROR = "Application configuration error prevented the operation from completing."; // Critical config issue
  public static final String MALFORMED_JSON = "The request body contains malformed JSON.";


  /**
   * Private constructor to prevent instantiation of this utility class.
   */
  private ApiErrorMessages() {
    // Throw an exception to prevent accidental instantiation via reflection, etc.
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }
}