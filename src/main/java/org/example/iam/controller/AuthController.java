// File: src/main/java/org/example/iam/controller/AuthController.java
package org.example.iam.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiError;
import org.example.iam.api.ApiSuccessResponse;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.ApiResponseMessages;
import org.example.iam.dto.*; // Import necessary DTOs
import org.example.iam.exception.OperationNotAllowedException;
import org.example.iam.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller handling authentication-related operations.
 * Provides endpoints for user login (JWT), email verification, password reset requests,
 * performing password resets, and resending verification emails.
 * All endpoints under this controller are generally public but interact with secured user data.
 */
@RestController
@RequestMapping("/api/v1/auth") // Base path for authentication endpoints
@RequiredArgsConstructor
@Slf4j
@Validated // Enables validation of method parameters like @RequestParam("token")
@Tag(name = "Authentication", description = "Endpoints for user login, verification, and password management")
public class AuthController {

  private final AuthService authService;

  /**
   * Handles user login requests using username/email and password.
   * On success, returns a JWT and user details.
   * Handles various authentication failure scenarios (bad credentials, locked, disabled, etc.).
   *
   * @param loginRequest DTO containing username/email and password.
   * @return ResponseEntity containing ApiResponse<LoginResponse> on success, or ApiError on failure.
   */
  @Operation(summary = "Authenticate User (JWT)",
          description = "Authenticates a user with username/email and password, returning a JWT upon success.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.LOGIN_SUCCESSFUL, // Use constant
                  content = @Content(mediaType = "application/json",
                          schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.AUTHENTICATION_FAILED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCOUNT_LOCKED + " / " + ApiErrorMessages.ACCOUNT_DISABLED + " / " + ApiErrorMessages.TEMPORARY_PASSWORD_REQUIRES_RESET, // Updated potential reasons
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "500", description = ApiErrorMessages.GENERAL_ERROR,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PostMapping("/login")
  public ResponseEntity<ApiSuccessResponse<LoginResponse>> authenticateUserJwt(
          @Valid @RequestBody LoginRequest loginRequest) {
    log.info("Received JWT login request for user/email: {}", loginRequest.getUsernameOrEmail());
    // AuthService handles authentication logic, including potential exceptions like BadCredentialsException etc.
    // GlobalExceptionHandler will map these exceptions to appropriate ApiError responses.
    LoginResponse loginResponse = authService.login(loginRequest);
    // Determine appropriate success message based on requiresPasswordChange flag
    String successMessage = loginResponse.isRequiresPasswordChange() ? ApiResponseMessages.TEMPORARY_PASSWORD_LOGIN : ApiResponseMessages.LOGIN_SUCCESSFUL;
    ApiSuccessResponse<LoginResponse> response = ApiSuccessResponse.ok(loginResponse, successMessage); // Use dynamic success message
    return ResponseEntity.ok(response);
  }

  /**
   * Verifies a user's email address using a provided token.
   * Activates the user account upon successful verification.
   *
   * @param token The verification token received by the user (usually via email).
   * @return ResponseEntity containing ApiResponse<Void> on success, or ApiError on failure (invalid/expired token).
   */
  @Operation(summary = "Verify User Email",
          description = "Verifies a user's email address using a token sent during registration or creation.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.VERIFICATION_SUCCESSFUL, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.VERIFICATION_TOKEN_INVALID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.USER_ALREADY_ENABLED, // Add forbidden if already enabled
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "410", description = ApiErrorMessages.VERIFICATION_TOKEN_EXPIRED, // GONE for expired
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping("/verify-email")
  public ResponseEntity<ApiSuccessResponse<Void>> verifyEmail(
          @Parameter(description = "The verification token from the email link", required = true)
          @RequestParam("token") @NotBlank(message = "Verification token cannot be blank") String token) {
    // Log only prefix for security
    log.info("Received email verification request with token prefix: {}", token.substring(0, Math.min(token.length(), 8)));
    authService.verifyEmail(token); // Handles token validation and user activation
    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(ApiResponseMessages.VERIFICATION_SUCCESSFUL); // Use constant
    return ResponseEntity.ok(response);
  }

  /**
   * Initiates the password reset process for a user based on their email address.
   * If the email exists, a password reset token is generated and sent via email.
   * Always returns a success response to prevent email enumeration attacks.
   *
   * @param forgotPasswordRequest DTO containing the user's primary email address.
   * @return ResponseEntity containing ApiResponse<Void>.
   */
  @Operation(summary = "Request Password Reset",
          description = "Sends a password reset link to the user's primary email address if the account exists.")
  @ApiResponses(value = {
          // Always return 200 OK to prevent leaking information about email existence
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.PASSWORD_RESET_REQUEST_SUCCESS, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT, // For invalid email format in DTO
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
  })
  @PostMapping("/forgot-password")
  public ResponseEntity<ApiSuccessResponse<Void>> forgotPassword(
          @Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest) {
    log.info("Received forgot password request for email: {}", forgotPasswordRequest.getEmail());
    authService.forgotPassword(forgotPasswordRequest.getEmail()); // Handles logic and email sending
    // Always return a generic success message regardless of whether the user existed.
    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(ApiResponseMessages.PASSWORD_RESET_REQUEST_SUCCESS); // Use constant
    log.debug("Forgot password request processing completed for email (response sent): {}",
            forgotPasswordRequest.getEmail());
    return ResponseEntity.ok(response);
  }

  /**
   * Resets a user's password using a valid password reset token.
   * Requires the token, new password, and confirmation of the new password.
   *
   * @param resetPasswordRequest DTO containing token, new password, and confirmation.
   * @return ResponseEntity containing ApiResponse<Void> on success, or ApiError on failure.
   */
  @Operation(summary = "Reset Password Using Token",
          description = "Sets a new password for the user using a valid token received via email.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.PASSWORD_RESET_SUCCESS, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.PASSWORD_RESET_TOKEN_INVALID + " / " + ApiErrorMessages.PASSWORD_MISMATCH,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "410", description = ApiErrorMessages.PASSWORD_RESET_TOKEN_EXPIRED, // GONE for expired
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PostMapping("/reset-password")
  public ResponseEntity<ApiSuccessResponse<Void>> resetPassword(
          @Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
    // Log only prefix for security
    String tokenPrefix = resetPasswordRequest.getToken().substring(0, Math.min(resetPasswordRequest.getToken().length(), 8));
    log.info("Received password reset request with token prefix: {}", tokenPrefix);
    authService.resetPassword(resetPasswordRequest); // Handles token validation and password update
    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(ApiResponseMessages.PASSWORD_RESET_SUCCESS); // Use constant
    log.info("Password reset successful for token prefix: {}", tokenPrefix);
    return ResponseEntity.ok(response);
  }

  /**
   * Resends the verification email to a user who hasn't verified their account yet.
   * Only applicable if the user exists and is not already enabled.
   *
   * @param resendRequest DTO containing the user's primary email address.
   * @return ResponseEntity containing ApiResponse<Void>. Returns specific error if already enabled.
   */
  @Operation(summary = "Resend Verification Email",
          description = "Requests a new verification email to be sent if the user exists and is not yet enabled.")
  @ApiResponses(value = {
          // Return 200 OK on success or if user doesn't exist
          @ApiResponse(responseCode = "200", description = "If your account exists and requires verification, a new email has been sent.",
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT, // For invalid email format in DTO
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.USER_ALREADY_ENABLED, // Use 403 Forbidden if already enabled
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PostMapping("/resend-verification")
  public ResponseEntity<ApiSuccessResponse<Void>> resendVerificationEmail(
          @Valid @RequestBody ResendVerificationRequest resendRequest) {
    log.info("Received resend verification email request for: {}", resendRequest.getEmail());
    try {
      authService.resendVerificationEmail(resendRequest.getEmail());
    } catch (OperationNotAllowedException e) {
      // Catch the specific exception if the user is already enabled
      // GlobalExceptionHandler will handle mapping this to a 403 response
      log.warn("Resend verification failed for {}: {}", resendRequest.getEmail(), e.getMessage());
      throw e; // Re-throw for GlobalExceptionHandler
    }
    // Always return a generic success message if no exception (avoids confirming email existence/status).
    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(
            "If your account exists and requires verification, a new email has been sent."); // Keep generic message
    log.debug("Resend verification request processing completed for email (response sent): {}",
            resendRequest.getEmail());
    return ResponseEntity.ok(response);
  }
}