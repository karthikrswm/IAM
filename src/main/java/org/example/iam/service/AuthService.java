// File: src/main/java/org/example/iam/service/AuthService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.ApiResponseMessages;
import org.example.iam.constant.AuditEventType;
import org.example.iam.dto.*;
import org.example.iam.entity.Organization; // Import Organization for helper method
import org.example.iam.entity.User;
import org.example.iam.entity.VerificationToken;
import org.example.iam.exception.*;
import org.example.iam.repository.UserRepository;
import org.example.iam.repository.VerificationTokenRepository;
import org.example.iam.security.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy; // Import Lazy
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
// Removed unused UsernameNotFoundException import as it's handled by UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service layer responsible for handling core authentication operations, including:
 * - User login via username/password (JWT flow).
 * - Email verification token generation, validation, and processing.
 * - Password reset token generation, validation, and processing.
 * - Resending verification emails.
 * <p>
 * Interacts with Spring Security's AuthenticationManager, JWT utilities, data repositories,
 * notification services, and auditing services.
 * </p>
 */
@Service
@RequiredArgsConstructor // Creates constructor for final fields
@Slf4j
public class AuthService {

  // --- Dependencies ---
  private final AuthenticationManager authenticationManager;
  private final JwtUtils jwtUtils;
  private final UserRepository userRepository; // Direct repo access for finding users by email/username
  private final VerificationTokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuditEventService auditEventService;
  private final NotificationService notificationService;
  private final @Lazy UserService userService; // Lazy inject UserService

  // --- Configuration Properties ---
  @Value("${security.verification.token.expire-minutes:1440}") // Default 24 hours
  private int verificationTokenExpirationMinutes;

  @Value("${security.password-reset.token.expire-minutes:60}")    // Default 1 hour
  private int passwordResetTokenExpirationMinutes;

  /**
   * Authenticates a user based on login request (username/email and password).
   * If successful, generates a JWT, updates user login status, logs the event, and returns login details.
   * If failed, updates failure count, logs the event, and throws appropriate exception.
   *
   * @param loginRequest DTO containing login credentials.
   * @return LoginResponse DTO containing JWT and user info.
   * @throws AuthenticationException      if authentication fails (e.g., BadCredentialsException).
   * @throws OperationNotAllowedException if login is disallowed due to account status (Locked, Disabled, CredentialsExpired).
   */
  @Transactional // Needed for user status updates (e.g., resetting lock count, last login)
  public LoginResponse login(LoginRequest loginRequest) {
    String usernameOrEmail = loginRequest.getUsernameOrEmail();
    log.info("Processing login request for user/email: {}", usernameOrEmail);

    Authentication authentication;
    User user; // Hold the authenticated user details
    String actorForAudit = usernameOrEmail; // Use input initially for potential failure logs
    UUID orgIdForAudit = null; // Org ID for logging

    try {
      // 1. Attempt authentication via Spring Security AuthenticationManager
      authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(usernameOrEmail, loginRequest.getPassword())
      );

      // 2. Authentication successful - update context and extract details
      SecurityContextHolder.getContext().setAuthentication(authentication);
      user = (User) authentication.getPrincipal();
      actorForAudit = user.getUsername(); // Use actual username for success audit
      orgIdForAudit = (user.getOrganization() != null) ? user.getOrganization().getId() : null;

      log.info("User '{}' successfully authenticated.", actorForAudit);

      // Check for temporary password AFTER successful authentication
      if (user.isTemporaryPassword()) {
        log.warn("User '{}' logged in successfully but requires mandatory password change (temporary password flag is set).", actorForAudit);
      }

      // 3. Perform post-login updates (reset fail count, update last login) via UserService
      userService.handleSuccessfulLogin(user.getId());

      // 4. Generate JWT
      String jwt = jwtUtils.generateToken(authentication); // Use authenticated object
      Instant expiry = jwtUtils.extractExpirationDate(jwt).toInstant();

      // 5. Build response DTO
      LoginResponse response = LoginResponse.builder()
              .userId(user.getId())
              .username(actorForAudit)
              .organizationId(orgIdForAudit)
              .accessToken(jwt)
              .expiresAt(expiry)
              .roles(user.getRoles().stream().map(r -> r.getRoleType().getRoleName()).collect(Collectors.toSet()))
              .requiresPasswordChange(user.isTemporaryPassword())
              .build();

      // 6. Log success audit event
      auditEventService.logEvent(AuditEventType.LOGIN_SUCCESS,
              String.format("User '%s' logged in successfully", actorForAudit), actorForAudit,
              "SUCCESS",
              "USER", user.getId().toString(), orgIdForAudit,
              null);
      log.info("Login successful for user '{}'. JWT generated.", actorForAudit);
      return response;

    } catch (AuthenticationException e) {
      // --- Handle Specific Authentication Failures ---
      orgIdForAudit = findOrgIdForUser(usernameOrEmail).orElse(null);
      String failureReason;

      if (e instanceof BadCredentialsException) {
        log.warn("Login failed for '{}': Invalid credentials.", usernameOrEmail);
        userService.handleFailedLoginAttempt(usernameOrEmail);
        failureReason = ApiErrorMessages.BAD_CREDENTIALS;
        auditEventService.logFailureEvent(AuditEventType.LOGIN_FAILURE,
                String.format("Login failed for '%s'", usernameOrEmail), actorForAudit,
                "USER_CREDENTIALS", actorForAudit, orgIdForAudit,
                failureReason);
        throw e;
      } else if (e instanceof LockedException) {
        log.warn("Login failed for '{}': Account locked.", usernameOrEmail);
        failureReason = ApiErrorMessages.ACCOUNT_LOCKED;
        auditEventService.logFailureEvent(AuditEventType.LOGIN_FAILURE,
                String.format("Login failed for '%s'", usernameOrEmail), actorForAudit,
                "USER_ACCOUNT", actorForAudit, orgIdForAudit,
                failureReason);
        throw new OperationNotAllowedException(failureReason, e);
      } else if (e instanceof DisabledException) {
        log.warn("Login failed for '{}': Account disabled.", usernameOrEmail);
        failureReason = ApiErrorMessages.ACCOUNT_DISABLED;
        auditEventService.logFailureEvent(AuditEventType.LOGIN_FAILURE,
                String.format("Login failed for '%s'", usernameOrEmail), actorForAudit,
                "USER_ACCOUNT", actorForAudit, orgIdForAudit,
                failureReason);
        throw new OperationNotAllowedException(failureReason, e);
      } else if (e instanceof CredentialsExpiredException) {
        log.warn("Login failed for '{}': Credentials expired (likely temporary password needs reset).", usernameOrEmail);
        failureReason = ApiErrorMessages.TEMPORARY_PASSWORD_REQUIRES_RESET;
        auditEventService.logFailureEvent(AuditEventType.LOGIN_FAILURE,
                String.format("Login failed for '%s'", usernameOrEmail), actorForAudit,
                "USER_CREDENTIALS", actorForAudit, orgIdForAudit,
                failureReason);
        throw new OperationNotAllowedException(failureReason, e);
      } else {
        failureReason = ApiErrorMessages.AUTHENTICATION_FAILED;
        log.error("Unexpected authentication error for '{}': {}", usernameOrEmail, e.getMessage(), e);
        auditEventService.logFailureEvent(AuditEventType.LOGIN_FAILURE,
                String.format("Login failed for '%s'", usernameOrEmail), actorForAudit,
                "SYSTEM", actorForAudit, orgIdForAudit,
                "Unknown authentication error: " + e.getMessage());
        throw e;
      }
    }
  }

  /**
   * Creates a new verification token for the given user, deletes any existing ones of the same type,
   * persists the new token, and triggers sending the verification email.
   *
   * @param user              The user requiring verification.
   * @param temporaryPassword (Optional) The temporary password to include in the email (handle securely!).
   */
  @Transactional // Ensures token deletion and creation are atomic
  public void createAndSendVerificationToken(User user, String temporaryPassword) {
    if (user == null || user.getId() == null) {
      log.error("Cannot create verification token for null user or user without ID.");
      return;
    }
    log.debug("Creating verification token for user '{}' (ID: {})", user.getUsername(), user.getId());

    // 1. Delete existing email verification tokens for this user
    int deletedCount = tokenRepository.deleteByUserAndTokenType(user, VerificationToken.TokenType.EMAIL_VERIFICATION);
    if (deletedCount > 0) {
      log.info("Deleted {} existing email verification token(s) for user '{}'", deletedCount, user.getUsername());
    }

    // 2. Generate new token
    String tokenString = UUID.randomUUID().toString();
    Instant expiryDate = Instant.now().plus(verificationTokenExpirationMinutes, ChronoUnit.MINUTES);

    VerificationToken token = VerificationToken.builder()
            .token(tokenString)
            .user(user)
            .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
            .expiryDate(expiryDate)
            .build();

    // 3. Save token
    VerificationToken savedToken = tokenRepository.save(token);

    // 4. Log audit event
    auditEventService.logEvent(AuditEventType.VERIFICATION_EMAIL_SENT,
            String.format("Verification email sending initiated for '%s'", user.getPrimaryEmail()),
            "SYSTEM", // Action performed by the system
            "SUCCESS",
            "USER", user.getId().toString(), // Target user
            user.getOrganization() != null ? user.getOrganization().getId() : null, // Org context
            "Token ID: " + savedToken.getId()); // Details

    // 5. Trigger email sending (asynchronously)
    notificationService.sendVerificationEmail(user, tokenString, temporaryPassword);
    log.debug("Verification email sending triggered for user '{}'", user.getUsername());
  }


  /**
   * Verifies a user's email using the provided token. Enables the user account if verification is successful.
   * Deletes the token after use (whether successful or not).
   *
   * @param tokenString The verification token string.
   * @throws InvalidTokenException if the token is not found or has the wrong type.
   * @throws TokenExpiredException if the token has expired.
   * @throws OperationNotAllowedException if the user is already enabled.
   */
  @Transactional // Ensures token validation, user update, and token deletion are atomic
  public void verifyEmail(String tokenString) {
    String tokenPrefix = tokenString.substring(0, Math.min(tokenString.length(), 8));
    log.info("Attempting email verification with token prefix: {}", tokenPrefix);

    VerificationToken verificationToken = validateTokenInternal(tokenString, VerificationToken.TokenType.EMAIL_VERIFICATION);
    User user = verificationToken.getUser(); // User guaranteed to be non-null by validateTokenInternal

    if (user.isEnabled()) {
      log.warn("Attempt to verify email for already enabled user '{}' (ID: {}). Token ID: {}",
              user.getUsername(), user.getId(), verificationToken.getId());
      // Log the event but throw exception to inform client
      auditEventService.logEvent(AuditEventType.EMAIL_VERIFIED, // Log verification attempt outcome
              String.format("Attempt to use valid verification token for already enabled user '%s'", user.getUsername()),
              user.getUsername(), // Actor is the user clicking the link
              "FAILURE",
              "VERIFICATION_TOKEN", verificationToken.getId().toString(), // Target is the token
              user.getOrganization() != null ? user.getOrganization().getId() : null,
              ApiErrorMessages.USER_ALREADY_ENABLED); // Detail
      // Delete the now-useless token
      tokenRepository.delete(verificationToken);
      throw new OperationNotAllowedException(ApiErrorMessages.USER_ALREADY_ENABLED);
    }

    // Enable the user account via UserService
    userService.enableAccount(user.getId()); // UserService handles its own audit log for USER_ENABLED

    // Log successful email verification audit event
    auditEventService.logEvent(AuditEventType.EMAIL_VERIFIED,
            String.format("Email verified successfully for user '%s'", user.getUsername()),
            user.getUsername(), // Actor is the user
            "SUCCESS",
            "USER", user.getId().toString(), // Target is the user
            user.getOrganization() != null ? user.getOrganization().getId() : null,
            "Token ID: " + verificationToken.getId()); // Detail includes token used


    // Delete the used token
    tokenRepository.delete(verificationToken);
    log.info("Email successfully verified for user '{}'. Token deleted.", user.getUsername());
  }

  /**
   * Initiates the password reset process for a given email address.
   * Finds the user, generates a password reset token, and sends the reset email.
   * Does not reveal whether the email address exists to prevent enumeration attacks.
   *
   * @param email The user's primary email address.
   */
  @Transactional
  public void forgotPassword(String email) {
    String processedEmail = email.toLowerCase().trim();
    log.info("Processing forgot password request for email: {}", processedEmail);

    Optional<User> userOptional = userRepository.findByPrimaryEmailIgnoreCase(processedEmail);

    if (userOptional.isPresent()) {
      User user = userOptional.get();
      String username = user.getUsername();
      UUID userId = user.getId();
      UUID orgId = user.getOrganization() != null ? user.getOrganization().getId() : null;
      log.debug("User found for password reset request: {}", username);

      // Invalidate previous password reset tokens
      int deletedCount = tokenRepository.deleteByUserAndTokenType(user, VerificationToken.TokenType.PASSWORD_RESET);
      if (deletedCount > 0) {
        log.info("Deleted {} old password reset token(s) for user '{}'", deletedCount, username);
      }

      // Create and save new token
      String tokenString = UUID.randomUUID().toString();
      Instant expiryDate = Instant.now().plus(passwordResetTokenExpirationMinutes, ChronoUnit.MINUTES);
      VerificationToken resetToken = VerificationToken.builder()
              .token(tokenString)
              .user(user)
              .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
              .expiryDate(expiryDate)
              .build();
      VerificationToken savedToken = tokenRepository.save(resetToken);

      // Log audit event for request
      auditEventService.logEvent(AuditEventType.PASSWORD_RESET_REQUESTED,
              String.format("Password reset requested for user '%s' (Email: %s)", username, processedEmail),
              username, // Actor is the user whose password is being reset
              "SUCCESS",
              "USER", userId.toString(), orgId, // Target user
              "Token ID: " + savedToken.getId());

      // Send notification email
      notificationService.sendPasswordResetEmail(user, tokenString);
      log.debug("Password reset email sending triggered for user '{}'", username);

    } else {
      // User not found - Log this event but do not inform the client
      log.warn("Password reset requested for non-existent email: {}. No email sent.", processedEmail);
      auditEventService.logFailureEvent(AuditEventType.PASSWORD_RESET_REQUESTED,
              "Password reset requested for an email address not found in system.",
              processedEmail, // Actor is the email submitted
              ApiErrorMessages.USER_NOT_FOUND_USERNAME);
    }
  }

  /**
   * Resets a user's password using a provided token and new password details.
   * Validates the token, checks password policies (match, complexity handled by service/validation),
   * updates the user's password, and deletes the used token.
   *
   * @param request DTO containing the reset token, new password, and confirmation.
   * @throws InvalidTokenException if the token is invalid or wrong type.
   * @throws TokenExpiredException if the token is expired.
   * @throws BadRequestException if passwords don't match or violate other rules (e.g., same as old).
   */
  @Transactional
  public void resetPassword(ResetPasswordRequest request) {
    String tokenString = request.getToken();
    String tokenPrefix = tokenString.substring(0, Math.min(tokenString.length(), 8));
    log.info("Attempting password reset with token prefix: {}", tokenPrefix);

    // 1. Validate the token
    VerificationToken resetToken = validateTokenInternal(tokenString, VerificationToken.TokenType.PASSWORD_RESET);
    User user = resetToken.getUser();
    UUID userId = user.getId();
    String username = user.getUsername();
    UUID userOrgId = user.getOrganization() != null ? user.getOrganization().getId() : null;
    UUID tokenId = resetToken.getId();
    log.debug("Password reset token validated successfully for user '{}' (Token ID: {})", username, tokenId);

    // 2. Perform password policy checks
    if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
      log.warn("Password reset failed for user '{}': New password is the same as the old password.", username);
      auditEventService.logFailureEvent(AuditEventType.PASSWORD_RESET_FAILURE,
              String.format("Password reset failed for user '%s'", username), username,
              "USER_CREDENTIALS", userId.toString(), userOrgId,
              "Attempted to set same password. Token ID: " + tokenId);
      throw new BadRequestException(ApiErrorMessages.PASSWORD_MISMATCH);
    }

    // 3. Update user password via UserService
    String newEncodedPassword = passwordEncoder.encode(request.getNewPassword());
    // <<< CORRECTED Method Call: Pass username as actor for self-reset >>>
    userService.updatePasswordAndFlags(userId, newEncodedPassword, username);

    // 4. Delete the used token
    tokenRepository.delete(resetToken);
    log.info("Password reset successful for user '{}' (ID: {}). Reset token (ID: {}) deleted.", username, userId, tokenId);

    // 5. Send confirmation email
    notificationService.sendPasswordChangeConfirmationEmail(user);
  }


  /**
   * Resends the verification email to a user specified by email address.
   * Only proceeds if the user exists and is not already enabled.
   *
   * @param email The primary email address of the user.
   * @throws OperationNotAllowedException if the user is already enabled.
   * (User not found is handled silently).
   */
  @Transactional
  public void resendVerificationEmail(String email) {
    String processedEmail = email.toLowerCase().trim();
    log.info("Processing resend verification email request for: {}", processedEmail);

    Optional<User> userOptional = userRepository.findByPrimaryEmailIgnoreCase(processedEmail);

    if (userOptional.isEmpty()) {
      log.warn("Resend verification requested for non-existent email: {}. No action taken.", processedEmail);
      return; // Exit silently
    }

    User user = userOptional.get();

    if (user.isEnabled()) {
      log.warn("Resend verification requested for already enabled user: '{}' (ID: {}).", user.getUsername(), user.getId());
      auditEventService.logEvent(AuditEventType.VERIFICATION_EMAIL_SENT,
              "Resend verification requested but user already enabled",
              processedEmail,
              "FAILURE",
              "USER", user.getId().toString(),
              user.getOrganization() != null ? user.getOrganization().getId() : null,
              ApiErrorMessages.USER_ALREADY_ENABLED);
      throw new OperationNotAllowedException(ApiErrorMessages.USER_ALREADY_ENABLED);
    }

    log.info("Proceeding to resend verification email for user: '{}' (ID: {})", user.getUsername(), user.getId());
    // Pass null for temporary password as this isn't initial creation
    createAndSendVerificationToken(user, null);
  }


  // --- Internal Helper Methods ---

  /**
   * Internal helper to validate a token string against type and expiry.
   * Throws specific exceptions on failure and logs audit events.
   * Guarantees returned token has a non-null User.
   *
   * @param tokenString  The token string from the request.
   * @param expectedType The expected {@link VerificationToken.TokenType}.
   * @return The valid {@link VerificationToken} entity.
   * @throws InvalidTokenException if token not found or wrong type.
   * @throws TokenExpiredException if token is expired.
   * @throws ConfigurationException if token data is inconsistent (e.g., missing user).
   */
  private VerificationToken validateTokenInternal(String tokenString, VerificationToken.TokenType expectedType) {
    String tokenPrefix = tokenString.substring(0, Math.min(tokenString.length(), 8));
    log.debug("Validating token (Type: {}) with prefix: {}", expectedType, tokenPrefix);

    final String invalidTokenMessage = (expectedType == VerificationToken.TokenType.EMAIL_VERIFICATION)
            ? ApiErrorMessages.VERIFICATION_TOKEN_INVALID
            : ApiErrorMessages.PASSWORD_RESET_TOKEN_INVALID;

    final String expiredTokenMessage = (expectedType == VerificationToken.TokenType.EMAIL_VERIFICATION)
            ? ApiErrorMessages.VERIFICATION_TOKEN_EXPIRED
            : ApiErrorMessages.PASSWORD_RESET_TOKEN_EXPIRED;


    // 1. Find token by string
    VerificationToken token = tokenRepository.findByToken(tokenString).orElseThrow(() -> {
      log.warn("Token validation failed: Token string prefix '{}' not found.", tokenPrefix);
      auditEventService.logFailureEvent(
              AuditEventType.TOKEN_VALIDATION_FAILURE,
              "Token validation failed (Not Found)",
              "Unknown",
              "Token prefix: " + tokenPrefix + "...");
      return new InvalidTokenException(invalidTokenMessage);
    });

    // Token found, extract context for logging
    UUID tokenId = token.getId();
    User tokenUser = token.getUser();
    String username = tokenUser != null ? tokenUser.getUsername() : "UNKNOWN_USER";
    UUID orgId = (tokenUser != null && tokenUser.getOrganization() != null)
            ? tokenUser.getOrganization().getId() : null;

    // 2. Check Token Type
    if (token.getTokenType() != expectedType) {
      log.warn("Token validation failed: Token ID '{}' (User: '{}') has wrong type. Expected: {}, Actual: {}",
              tokenId, username, expectedType, token.getTokenType());
      auditEventService.logFailureEvent(AuditEventType.TOKEN_VALIDATION_FAILURE,
              "Token validation failed (Wrong Type)", username,
              "VERIFICATION_TOKEN", tokenId.toString(), orgId,
              "Expected: " + expectedType + ", Actual: " + token.getTokenType());
      tokenRepository.delete(token);
      throw new InvalidTokenException(invalidTokenMessage);
    }

    // 3. Check if Token Expired
    if (token.isExpired()) {
      log.warn("Token validation failed: Token ID '{}' (User: '{}') expired at {}.",
              tokenId, username, token.getExpiryDate());
      auditEventService.logFailureEvent(AuditEventType.TOKEN_VALIDATION_FAILURE,
              "Token validation failed (Expired)", username,
              "VERIFICATION_TOKEN", tokenId.toString(), orgId,
              "Expiry: " + token.getExpiryDate());
      tokenRepository.delete(token);
      throw new TokenExpiredException(expiredTokenMessage);
    }

    // 4. Check Data Integrity (User should exist)
    if (tokenUser == null) {
      log.error("CRITICAL: Data integrity error. Token ID '{}' exists but is not linked to a user.", tokenId);
      auditEventService.logFailureEvent(AuditEventType.TOKEN_VALIDATION_FAILURE,
              "Token validation failed (Orphaned Token - No User Link)", "SYSTEM",
              "VERIFICATION_TOKEN", tokenId.toString(), null,
              "Token has no associated user.");
      tokenRepository.delete(token);
      throw new ConfigurationException("Token integrity error: User link missing for token ID " + tokenId);
    }

    // If all checks pass:
    log.debug("Token ID '{}' validated successfully for user '{}'.", tokenId, username);
    auditEventService.logEvent(AuditEventType.TOKEN_VALIDATION_SUCCESS,
            String.format("Token type %s validated successfully for user %s", expectedType, username),
            username, "SUCCESS", "VERIFICATION_TOKEN", tokenId.toString(), orgId, null);
    return token;
  }

  /**
   * Helper method to find the Organization ID for a user based on their username or email.
   * Used for enriching audit logs when the primary operation fails before full user context is loaded.
   * Returns Optional.empty() if the user or their organization cannot be found.
   */
  private Optional<UUID> findOrgIdForUser(String usernameOrEmail) {
    return userRepository.findByUsernameIgnoreCase(usernameOrEmail)
            .or(() -> userRepository.findByPrimaryEmailIgnoreCase(usernameOrEmail))
            .map(User::getOrganization)
            .filter(Objects::nonNull)
            .map(Organization::getId);
  }
}