// File: src/main/java/org/example/iam/constant/ApiResponseMessages.java
package org.example.iam.constant;

import org.example.iam.api.ApiSuccessResponse;

/**
 * Defines standardized success and informational messages used in API responses
 * ({@link ApiSuccessResponse}).
 * <p>
 * Using constants promotes consistency in client-facing messages and simplifies maintenance.
 * </p>
 * This class is final and cannot be instantiated.
 */
public final class ApiResponseMessages {

  // --- Authentication & Verification ---
  public static final String SIGNUP_SUCCESS = "User registered successfully. Please check your primary email for a verification link."; // Used if self-signup were enabled
  public static final String LOGIN_SUCCESSFUL = "Login successful.";
  public static final String LOGOUT_SUCCESS = "Logout successful."; // <<< ADDED
  public static final String VERIFICATION_SUCCESSFUL = "Account verified and enabled successfully.";
  public static final String PASSWORD_RESET_REQUEST_SUCCESS = "If an account with the provided email exists, a password reset link has been sent."; // Generic message for security
  public static final String PASSWORD_RESET_SUCCESS = "Password has been reset successfully.";
  public static final String PASSWORD_UPDATED_SUCCESS = "Your password has been updated successfully.";
  public static final String TEMPORARY_PASSWORD_LOGIN = "Login successful. Please change your temporary password immediately.";

  // --- Organization Management ---
  public static final String ORG_CREATED_SUCCESS = "Organization created successfully.";
  public static final String ORG_UPDATED_SUCCESS = "Organization updated successfully.";
  public static final String ORG_RETRIEVED_SUCCESS = "Organization details retrieved successfully.";
  public static final String ORG_DELETED_SUCCESS = "Organization deleted successfully.";
  public static final String ALL_ORGS_RETRIEVED_SUCCESS = "All organizations retrieved successfully.";
  public static final String ORG_SAML_CONFIG_UPDATED = "Organization SAML configuration updated successfully.";
  public static final String ORG_OAUTH2_CONFIG_UPDATED = "Organization OAuth2 configuration updated successfully.";
  public static final String ORG_CONFIG_RETRIEVED_SUCCESS = "Organization configuration retrieved successfully.";

  // --- User Management ---
  public static final String USER_CREATED_SUCCESS = "User created successfully. A verification email with temporary password instructions has been sent.";
  public static final String USER_UPDATED_SUCCESS = "User profile updated successfully.";
  public static final String USER_RETRIEVED_SUCCESS = "User details retrieved successfully.";
  public static final String USER_DELETED_SUCCESS = "User deleted successfully.";
  public static final String ALL_USERS_RETRIEVED_SUCCESS = "Users retrieved successfully.";
  public static final String USER_ENABLED_SUCCESS = "User enabled successfully.";
  public static final String USER_DISABLED_SUCCESS = "User disabled successfully.";

  // --- General / Miscellaneous ---
  public static final String OPERATION_SUCCESSFUL = "Operation completed successfully."; // Generic success
  public static final String RESOURCE_CREATED = "Resource created successfully."; // Generic create
  public static final String RESOURCE_UPDATED = "Resource updated successfully."; // Generic update
  public static final String RESOURCE_DELETED = "Resource deleted successfully."; // Generic delete
  public static final String PONG = "Pong"; // Often used for health check /ping endpoints

  /**
   * Private constructor to prevent instantiation of this utility class.
   */
  private ApiResponseMessages() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }
}