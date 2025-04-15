// File: src/main/java/org/example/iam/service/UserService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.AuditEventType;
import org.example.iam.constant.RoleType;
import org.example.iam.dto.CreateUserRequest;
import org.example.iam.dto.UpdatePasswordRequest;
import org.example.iam.dto.UpdateUserRequest;
import org.example.iam.dto.UserResponse;
import org.example.iam.entity.Organization;
import org.example.iam.entity.Role;
import org.example.iam.entity.User;
import org.example.iam.exception.*;
import org.example.iam.repository.OrganizationRepository;
import org.example.iam.repository.RoleRepository;
import org.example.iam.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy; // Import Lazy
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException; // Use Spring's exception
import org.springframework.security.authentication.BadCredentialsException; // Specific exception for password mismatch
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service layer containing business logic related to User account management.
 * Handles creation, retrieval, updates, deletion, password changes, account status (locking, expiry),
 * Just-In-Time (JIT) provisioning for SSO, and interaction with dependent services like auditing and notifications.
 */
@Service
//@RequiredArgsConstructor // Lombok constructor injection
@Slf4j
public class UserService {

  // --- Dependencies ---
  private final UserRepository userRepository;
  private final OrganizationRepository organizationRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuditEventService auditEventService;
  private final NotificationService notificationService;
  private final AuthService authService;

  // --- Password Generation Constants ---
  private static final String PASSWORD_LOWER = "abcdefghijklmnopqrstuvwxyz";
  private static final String PASSWORD_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String PASSWORD_DIGITS = "0123456789";
  private static final String PASSWORD_SPECIAL = "!@#$%^&*()-_=+"; // Adjust special characters as needed
  private static final String PASSWORD_CHARS = PASSWORD_LOWER + PASSWORD_UPPER + PASSWORD_DIGITS + PASSWORD_SPECIAL;
  private static final int TEMP_PASSWORD_LENGTH = 14; // Configurable length for temporary passwords
  // SecureRandom is thread-safe and should be reused
  private static final SecureRandom secureRandom = new SecureRandom();

  // --- Configuration Properties ---
  @Value("${security.account.lock.max-attempts:5}")
  private int maxFailedAttempts;

  @Value("${security.account.lock.duration-minutes:15}")
  private long lockDurationMinutes;

  public UserService(UserRepository userRepository,
                     OrganizationRepository organizationRepository,
                     RoleRepository roleRepository,
                     @Lazy PasswordEncoder passwordEncoder, // <<< Add @Lazy here
                     AuditEventService auditEventService,
                     @Lazy AuthService authService, // Keep this lazy too
                     NotificationService notificationService
          /* Add other final fields here */ ) {
    this.userRepository = userRepository;
    this.organizationRepository = organizationRepository;
    this.roleRepository = roleRepository;
    this.passwordEncoder = passwordEncoder;
    this.auditEventService = auditEventService;
    this.authService = authService;
    this.notificationService = notificationService;
    // Assign other final fields
  }

  // --- User CRUD Operations ---

  /**
   * Creates a new user account within a specified organization.
   * Performs validation, authorization checks, generates a temporary password,
   * saves the user, logs an audit event, and triggers a verification email.
   *
   * @param request    DTO containing the new user's details.
   * @param actor      Username of the user performing the creation (ADMIN or SUPER).
   * @param actorOrgId UUID of the organization the actor belongs to.
   * @param actorRoles Set of roles assigned to the actor.
   * @return UserResponse DTO of the newly created user.
   * @throws ResourceNotFoundException if the target organization or required role doesn't exist.
   * @throws ConflictException         if username or primary email already exists.
   * @throws BadRequestException       if email domain validation fails.
   * @throws OperationNotAllowedException if trying to assign SUPER role.
   * @throws AccessDeniedException     if the actor lacks permission to create the user.
   * @throws ConfigurationException    if a required Role (ADMIN/USER) is missing from DB.
   */
  @Transactional // Ensure all operations (validation, save, audit, email trigger) are atomic
  public UserResponse createUser(CreateUserRequest request, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.info("Actor '{}' attempting to create user '{}' in organization '{}'", actor, request.getUsername(), request.getOrganizationId());

    // 1. Fetch Target Organization
    Organization targetOrg = organizationRepository.findById(request.getOrganizationId())
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, request.getOrganizationId())));

    // 2. Perform Authorization Check
    performCreateUserAuthorization(actor, actorOrgId, actorRoles, targetOrg, request.getRoleType());

    // 3. Validate Request Data (Uniqueness, Domains)
    validateUserCreationRequest(request, targetOrg);

    // 4. Fetch Required Role
    Role userRole = roleRepository.findByRoleType(request.getRoleType())
            .orElseThrow(() -> {
              log.error("Configuration Error: Role '{}' not found in database.", request.getRoleType());
              // This is an internal configuration issue, hence ConfigurationException
              return new ConfigurationException("Required role " + request.getRoleType() + " is not configured in the system.");
            });

    // 5. Generate & Encode Temporary Password
    String tempPassword = generateTemporaryPassword();
    String encodedPassword = passwordEncoder.encode(tempPassword);

    // 6. Build User Entity
    User newUser = User.builder()
            .username(request.getUsername().trim()) // Ensure trimmed
            .primaryEmail(request.getPrimaryEmail().toLowerCase().trim()) // Normalize email
            .secondaryEmail(request.getSecondaryEmail() != null ? request.getSecondaryEmail().toLowerCase().trim() : null)
            .phoneNumber(request.getPhoneNumber() != null ? request.getPhoneNumber().trim() : null)
            .password(encodedPassword)
            .organization(targetOrg)
            .temporaryPassword(true) // Requires change on first login
            .enabled(false) // Requires email verification
            .accountNonExpired(true) // Default state
            .accountNonLocked(true) // Default state
            .credentialsNonExpired(false) // Password needs immediate change/reset effectively
            .passwordChangedDate(Instant.now()) // Set initial change date
            .build();
    newUser.addRole(userRole); // Add the role relationship

    // 7. Save User
    User savedUser = userRepository.save(newUser); // createdBy/Date set by AuditingEntityListener
    log.info("User '{}' (ID: {}) created successfully by actor '{}' in Org '{}' (ID: {}) with role {}",
            savedUser.getUsername(), savedUser.getId(), actor, targetOrg.getOrgName(), targetOrg.getId(), request.getRoleType());

    // 8. Log Audit Event
    auditEventService.logEvent(
            AuditEventType.USER_CREATED,
            String.format("User '%s' created by %s", savedUser.getUsername(), actor),
            actor, "SUCCESS",
            "USER", savedUser.getId().toString(), // Target is the new user
            targetOrg.getId(), // Org context
            "Role assigned: " + request.getRoleType() // Details
    );

    // 9. Trigger Verification Email (via AuthService to avoid direct dependency cycle if possible)
    // Pass the plain temporary password here - **handle security implications**
    authService.createAndSendVerificationToken(savedUser, tempPassword);

    // 10. Return DTO representation
    return UserResponse.fromEntity(savedUser);
  }

  /**
   * Retrieves a user's details by their UUID.
   * Performs authorization check: SUPER user, ADMIN of the target user's org, or the user themselves.
   *
   * @param userId     UUID of the user to retrieve.
   * @param actor      Username of the requesting user.
   * @param actorOrgId UUID of the organization the actor belongs to.
   * @param actorRoles Set of roles assigned to the actor.
   * @return UserResponse DTO of the found user.
   * @throws ResourceNotFoundException if the user doesn't exist.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  @Transactional(readOnly = true) // Read-only operation
  public UserResponse getUserById(UUID userId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.debug("Actor '{}' attempting to retrieve user ID '{}'", actor, userId);

    User user = userRepository.findById(userId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.USER_NOT_FOUND_ID, userId)));

    // Perform authorization check
    authorizeUserAccess(actor, actorOrgId, actorRoles, user, "view");

    log.info("Successfully retrieved user '{}' (ID: {}) for actor '{}'", user.getUsername(), userId, actor);
    return UserResponse.fromEntity(user);
  }

  /**
   * Updates a user's profile information (secondary email, phone number).
   * Performs authorization check: SUPER user, ADMIN of the target user's org, or the user themselves.
   * Validates secondary email domain if provided.
   *
   * @param userId            UUID of the user to update.
   * @param request           DTO containing updated profile details.
   * @param actor             Username of the user performing the update.
   * @param actorOrgId        UUID of the organization the actor belongs to.
   * @param actorRoles        Set of roles assigned to the actor.
   * @return UserResponse DTO of the updated user.
   * @throws ResourceNotFoundException if the user doesn't exist.
   * @throws AccessDeniedException     if the actor lacks permission.
   * @throws ConflictException         if the secondary email domain is invalid.
   */
  @Transactional
  public UserResponse updateUser(UUID userId, UpdateUserRequest request, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.info("Actor '{}' attempting to update profile for user ID '{}'", actor, userId);

    User existingUser = userRepository.findById(userId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.USER_NOT_FOUND_ID, userId)));

    // Perform authorization check
    authorizeUserAccess(actor, actorOrgId, actorRoles, existingUser, "update");

    boolean changed = false;
    StringBuilder changes = new StringBuilder("Fields changed: ");
    UUID targetUserOrgId = (existingUser.getOrganization() != null) ? existingUser.getOrganization().getId() : null;


    // Update Secondary Email if changed
    String newSecondaryEmail = (request.getSecondaryEmail() != null) ? request.getSecondaryEmail().toLowerCase().trim() : null;
    if (!Objects.equals(newSecondaryEmail, existingUser.getSecondaryEmail())) {
      if (StringUtils.hasText(newSecondaryEmail)) {
        // Validate domain only if a new secondary email is provided
        validateSecondaryEmailDomain(newSecondaryEmail, targetUserOrgId);
      }
      log.debug("Updating secondary email for user ID '{}'", userId);
      existingUser.setSecondaryEmail(newSecondaryEmail);
      changed = true;
      changes.append("SecondaryEmail;");
    }

    // Update Phone Number if changed
    String newPhone = (request.getPhoneNumber() != null) ? request.getPhoneNumber().trim() : null;
    if (!Objects.equals(newPhone, existingUser.getPhoneNumber())) {
      log.debug("Updating phone number for user ID '{}'", userId);
      existingUser.setPhoneNumber(newPhone);
      changed = true;
      changes.append("PhoneNumber;");
    }

    User updatedUser = existingUser; // Assume no change initially
    if (changed) {
      updatedUser = userRepository.save(existingUser); // Save changes, triggers @LastModifiedBy/Date update
      log.info("User profile '{}' (ID: {}) updated successfully by actor '{}'", updatedUser.getUsername(), userId, actor);

      // Log audit event
      auditEventService.logEvent(
              AuditEventType.USER_UPDATED, // More specific type could be USER_PROFILE_UPDATED
              String.format("User profile '%s' updated", updatedUser.getUsername()),
              actor, "SUCCESS",
              "USER", userId.toString(), // Target user
              targetUserOrgId, // Org context
              changes.toString() // Details of changed fields
      );
    } else {
      log.info("No profile changes detected for user ID '{}'. Update skipped.", userId);
    }

    return UserResponse.fromEntity(updatedUser); // Return current state
  }


  /**
   * Retrieves a paginated list of users for a specific organization.
   * Requires SUPER role or ADMIN role of the target organization.
   *
   * @param organizationId UUID of the target organization.
   * @param actor          Username of the requesting user.
   * @param actorOrgId     UUID of the organization the actor belongs to.
   * @param actorRoles     Set of roles assigned to the actor.
   * @param pageable       Pagination and sorting information.
   * @return Page of UserResponse DTOs.
   * @throws ResourceNotFoundException if the organization doesn't exist.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  @Transactional(readOnly = true)
  public Page<UserResponse> getAllUsersByOrganization(UUID organizationId, String actor, UUID actorOrgId, Set<RoleType> actorRoles, Pageable pageable) {
    log.debug("Actor '{}' attempting to list users for organization ID '{}' with pageable: {}", actor, organizationId, pageable);

    // Authorization Check: Must be SUPER or ADMIN of the target organization
    boolean isSuper = actorRoles.contains(RoleType.SUPER);
    boolean isAdminOfTargetOrg = actorRoles.contains(RoleType.ADMIN) && Objects.equals(actorOrgId, organizationId);

    if (!isSuper && !isAdminOfTargetOrg) {
      log.warn("Authorization failed: Actor '{}' (Org: {}, Roles: {}) cannot list users for Org ID '{}'.",
              actor, actorOrgId, actorRoles, organizationId);
      throw new AccessDeniedException("User requires SUPER role or ADMIN role of the target organization to list users.");
    }

    // Check if organization exists before querying users
    if (!organizationRepository.existsById(organizationId)) {
      throw new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, organizationId));
    }

    Page<User> userPage = userRepository.findByOrganizationId(organizationId, pageable);
    log.info("Retrieved page {}/{} ({} users) for organization ID '{}' for actor '{}'",
            userPage.getNumber(), userPage.getTotalPages(), userPage.getNumberOfElements(), organizationId, actor);

    // Map the page of User entities to a page of UserResponse DTOs
    return userPage.map(UserResponse::fromEntity);
  }

  /**
   * Deletes a user account.
   * Enforces rules: Cannot delete self, cannot delete SUPER users, ADMINs can only delete USERs within their org.
   * Requires SUPER role or ADMIN role of the user's organization.
   *
   * @param userId     UUID of the user to delete.
   * @param actor      Username of the user performing the deletion.
   * @param actorOrgId UUID of the organization the actor belongs to.
   * @param actorRoles Set of roles assigned to the actor.
   * @throws ResourceNotFoundException    if the user doesn't exist.
   * @throws OperationNotAllowedException if attempting to delete self or SUPER user.
   * @throws AccessDeniedException        if the actor lacks permission based on role and target user.
   */
  @Transactional
  public void deleteUser(UUID userId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.warn("Actor '{}' attempting DESTRUCTIVE delete operation for user ID: {}", actor, userId);

    User userToDelete = userRepository.findById(userId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.USER_NOT_FOUND_ID, userId)));

    String targetUsername = userToDelete.getUsername();
    UUID targetOrgId = (userToDelete.getOrganization() != null) ? userToDelete.getOrganization().getId() : null;

    // --- Business Rule and Authorization Checks ---
    // 1. Cannot delete self
    if (targetUsername.equalsIgnoreCase(actor)) {
      log.warn("Delete failed: Actor '{}' attempted to delete self (ID: {})", actor, userId);
      throw new OperationNotAllowedException(ApiErrorMessages.CANNOT_DELETE_SELF);
    }
    // 2. Cannot delete SUPER users via API
    if (userToDelete.hasRole(RoleType.SUPER.getRoleName())) {
      log.warn("Delete failed: Actor '{}' attempted to delete SUPER user '{}' (ID: {})", actor, targetUsername, userId);
      throw new OperationNotAllowedException(ApiErrorMessages.CANNOT_DELETE_SUPER_USER);
    }

    // 3. Authorization based on actor's role and target user's role/org
    boolean isActorSuper = actorRoles.contains(RoleType.SUPER);
    boolean isActorAdmin = actorRoles.contains(RoleType.ADMIN);
    boolean isTargetAdmin = userToDelete.hasRole(RoleType.ADMIN.getRoleName());
    // Actor must be ADMIN of the *same organization* as the user being deleted
    boolean isActorAdminOfTargetOrg = isActorAdmin && Objects.equals(actorOrgId, targetOrgId);

    // SUPER user can delete any non-SUPER user
    boolean allowedBySuper = isActorSuper;
    // ADMIN can delete USERs in their own org, but NOT other ADMINs
    boolean allowedByAdmin = isActorAdminOfTargetOrg && !isTargetAdmin;

    if (!allowedBySuper && !allowedByAdmin) {
      String reason = isActorAdminOfTargetOrg ? "Admin cannot delete another Admin." : "Insufficient permissions.";
      log.warn("Authorization failed: Actor '{}' (Org: {}, Roles: {}) cannot delete user '{}' (ID: {}, Org: {}, IsAdmin: {}). Reason: {}",
              actor, actorOrgId, actorRoles, targetUsername, userId, targetOrgId, isTargetAdmin, reason);
      throw new AccessDeniedException("User does not have permission to delete this user account.");
    }
    // --- End Checks ---

    log.debug("Authorization successful for actor '{}' to delete user '{}'", actor, targetUsername);

    // Perform Deletion (Cascade should handle user_roles, VerificationTokens need manual/cascade delete)
    // Consider explicitly deleting related tokens first if cascade isn't set up for them.
    // int tokensDeleted = tokenRepository.deleteByUser(userToDelete);
    // log.debug("Deleted {} verification tokens for user '{}' before user deletion.", tokensDeleted, targetUsername);

    userRepository.delete(userToDelete);
    log.info("User '{}' (ID: {}) deleted successfully by actor '{}'.", targetUsername, userId, actor);

    // Log audit event
    auditEventService.logEvent(
            AuditEventType.USER_DELETED,
            String.format("User '%s' (ID: %s) deleted", targetUsername, userId),
            actor, "SUCCESS",
            "USER", userId.toString(), // Target resource ID
            targetOrgId, // Org context
            null
    );
  }

  /**
   * Updates the password for the currently authenticated user (self-service).
   * Requires current password verification. Checks new password policies.
   *
   * @param request       DTO containing current password, new password, and confirmation.
   * @param actorUsername Username of the user changing their password (from security context).
   * @throws ResourceNotFoundException if the user cannot be found (should not happen for authenticated user).
   * @throws BadCredentialsException   if the current password doesn't match.
   * @throws BadRequestException       if new passwords don't match or new password is same as old.
   */
  @Transactional
  public void updateUserPassword(UpdatePasswordRequest request, String actorUsername) {
    log.info("User '{}' attempting self-service password update.", actorUsername);

    User user = userRepository.findByUsernameIgnoreCase(actorUsername)
            .orElseThrow(() -> {
              // This should technically not happen if the user is authenticated
              log.error("CRITICAL: Authenticated user '{}' not found in repository during password update.", actorUsername);
              return new ResourceNotFoundException(String.format(ApiErrorMessages.USER_NOT_FOUND_USERNAME, actorUsername));
            });

    UUID userId = user.getId();
    UUID userOrgId = (user.getOrganization() != null) ? user.getOrganization().getId() : null;

    // 1. Verify Current Password
    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
      log.warn("Password update failed for user '{}': Incorrect current password provided.", actorUsername);
      // Log audit failure
      auditEventService.logFailureEvent(AuditEventType.PASSWORD_UPDATED,
              String.format("User '%s' password update failed", actorUsername), actorUsername,
              "USER_CREDENTIALS", userId.toString(), userOrgId,
              ApiErrorMessages.BAD_CREDENTIALS + " (Incorrect current password)");
      throw new BadCredentialsException(ApiErrorMessages.BAD_CREDENTIALS); // Use specific exception for incorrect current password
    }

    // 2. Check New Password Confirmation (Handled by @AssertTrue on DTO)

    // 3. Check if New Password is the Same as Old
    if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
      log.warn("Password update failed for user '{}': New password is the same as the current password.", actorUsername);
      auditEventService.logFailureEvent(AuditEventType.PASSWORD_UPDATED,
              String.format("User '%s' password update failed", actorUsername), actorUsername,
              "USER_CREDENTIALS", userId.toString(), userOrgId,
              "New password same as old");
      throw new BadRequestException("New password cannot be the same as the current password.");
    }

    // 4. Encode and Update Password (and related flags)
    String newEncodedPassword = passwordEncoder.encode(request.getNewPassword());
    updatePasswordAndFlags(userId, newEncodedPassword); // Use helper method

    // 5. Log Audit Success (handled within updatePasswordAndFlags)

    // 6. Send Confirmation Notification
    notificationService.sendPasswordChangeConfirmationEmail(user);
  }

  // --- JIT Provisioning ---

  /**
   * Finds an existing user by email or creates a new one during OAuth2 login (JIT provisioning).
   * Validates email domain against the organization. Enables user if found disabled.
   * Assigns default USER role on creation.
   *
   * @param organization   The organization determined from the OAuth2 registration ID.
   * @param email          The primary email extracted from the OAuth2 provider attributes.
   * @param usernameSource A string derived from provider attributes (e.g., email prefix, preferred_username, sub) to base the local username on.
   * @param providerId     Identifier of the OAuth2 provider/registration (for logging).
   * @param attributes     Original attributes from the provider (optional, for potential future use).
   * @return The found or newly created local User entity.
   * @throws BadRequestException if email domain doesn't match org or if email belongs to another org.
   * @throws ConfigurationException if the default USER role is not found.
   */
  @Transactional
  public User findOrCreateOauth2User(Organization organization, String email, String usernameSource, String providerId, Map<String, Object> attributes) {
    String processedEmail = email.toLowerCase().trim();
    log.debug("Processing OAuth2 JIT provisioning for email '{}' in organization '{}' (ID: {})",
            processedEmail, organization.getOrgName(), organization.getId());

    // Validate email belongs to the organization found via registrationId
    validateEmailDomain(processedEmail, organization.getOrgDomain());

    Optional<User> existingUserOpt = userRepository.findByPrimaryEmailIgnoreCase(processedEmail);

    if (existingUserOpt.isPresent()) {
      // --- User Found ---
      User user = existingUserOpt.get();
      log.info("Found existing user '{}' (ID: {}) for OAuth2 JIT provisioning via email '{}'",
              user.getUsername(), user.getId(), processedEmail);

      // Ensure the found user belongs to the *correct* organization (prevent hijacking)
      if (!Objects.equals(user.getOrganization().getId(), organization.getId())) {
        log.error("OAuth2 JIT Error: Email '{}' found but belongs to Org ID '{}', expected Org ID '{}'. Potential misconfiguration or attack.",
                processedEmail, user.getOrganization().getId(), organization.getId());
        throw new BadRequestException("User account email belongs to a different organization.");
      }

      // Handle login success actions (update last login, reset locks)
      handleSuccessfulLogin(user.getId());

      // If user was disabled (e.g., manually), re-enable them on successful SSO login? (Policy decision)
      if (!user.isEnabled()) {
        log.warn("Re-enabling disabled user '{}' (ID: {}) upon successful OAuth2 login.", user.getUsername(), user.getId());
        user.setEnabled(true);
        userRepository.save(user); // Save the enabled status change
        auditEventService.logEvent(AuditEventType.USER_ENABLED,
                String.format("User account '%s' automatically re-enabled via OAuth2 login", user.getUsername()),
                "OAUTH2_JIT", "SUCCESS", // Actor indicating JIT process
                "USER", user.getId().toString(), organization.getId(),
                "Provider ID: " + providerId);
      }
      // TODO: Consider updating roles based on claims from provider? (More complex)
      return user;
    } else {
      // --- User Not Found - Create New User ---
      log.info("No existing user found for email '{}'. Creating new user via OAuth2 JIT for organization '{}'.",
              processedEmail, organization.getOrgName());

      // Generate a unique local username
      String baseUsername = generateUsernameFromSource(usernameSource, processedEmail);
      String uniqueUsername = findAvailableUsername(baseUsername);

      // Generate a secure random password (user won't use it for OAuth2 login, but entity requires non-null)
      String randomPassword = generateTemporaryPassword(); // Use temp password generator for complexity
      String encodedPassword = passwordEncoder.encode(randomPassword);

      // Fetch the default USER role
      Role userRole = roleRepository.findByRoleType(RoleType.USER)
              .orElseThrow(() -> {
                log.error("Configuration Error: Default 'USER' role not found in database for JIT provisioning.");
                return new ConfigurationException("Default USER role not configured in the system.");
              });

      // Build the new user entity
      User newUser = User.builder()
              .username(uniqueUsername)
              .primaryEmail(processedEmail)
              .password(encodedPassword) // Store encoded random password
              .organization(organization)
              .enabled(true) // Enable immediately as they authenticated via trusted provider
              .temporaryPassword(false) // Password wasn't temporary from our system's perspective
              .credentialsNonExpired(true) // Credentials aren't expired
              .accountNonExpired(true)
              .accountNonLocked(true)
              .passwordChangedDate(Instant.now()) // Set baseline password change date
              .lastLoginDate(Instant.now()) // Set initial login date
              .build();
      newUser.addRole(userRole); // Assign default USER role

      // Save the new user
      User savedUser = userRepository.save(newUser);
      log.info("Created new user '{}' (ID: {}) via OAuth2 JIT for organization '{}'.",
              savedUser.getUsername(), savedUser.getId(), organization.getOrgName());

      // Log audit event for JIT creation
      auditEventService.logEvent(
              AuditEventType.USER_CREATED,
              String.format("User '%s' created via OAuth2 JIT provisioning", savedUser.getUsername()),
              "OAUTH2_JIT_" + providerId, // Actor indicating provider and JIT
              "SUCCESS",
              "USER", savedUser.getId().toString(), // Target user
              organization.getId(), // Org context
              "Email: " + processedEmail + ", Role: USER" // Details
      );
      return savedUser;
    }
  }


  /**
   * Finds an existing user by email or creates a new one during SAML login (JIT provisioning).
   * Logic is very similar to findOrCreateOauth2User.
   *
   * @param organization   The organization determined from the SAML registration ID.
   * @param email          The primary email extracted from the SAML assertion attributes.
   * @param usernameSource A string derived from SAML attributes (e.g., NameID, uid) to base the local username on.
   * @param registrationId Identifier of the SAML registration (for logging).
   * @param attributes     Original attributes from the SAML assertion (optional).
   * @return The found or newly created local User entity.
   * @throws BadRequestException if email domain doesn't match org or if email belongs to another org.
   * @throws ConfigurationException if the default USER role is not found.
   */
  @Transactional
  public User findOrCreateSamlUser(Organization organization, String email, String usernameSource, String registrationId, Map<String, List<Object>> attributes) {
    String processedEmail = email.toLowerCase().trim();
    log.debug("Processing SAML JIT provisioning for email '{}' in organization '{}' (ID: {})",
            processedEmail, organization.getOrgName(), organization.getId());

    // Validate email belongs to the organization found via registrationId
    validateEmailDomain(processedEmail, organization.getOrgDomain());

    Optional<User> existingUserOpt = userRepository.findByPrimaryEmailIgnoreCase(processedEmail);

    if (existingUserOpt.isPresent()) {
      // --- User Found ---
      User user = existingUserOpt.get();
      log.info("Found existing user '{}' (ID: {}) for SAML JIT provisioning via email '{}'",
              user.getUsername(), user.getId(), processedEmail);

      // Ensure the found user belongs to the *correct* organization
      if (!Objects.equals(user.getOrganization().getId(), organization.getId())) {
        log.error("SAML JIT Error: Email '{}' found but belongs to Org ID '{}', expected Org ID '{}'. Potential misconfiguration or attack.",
                processedEmail, user.getOrganization().getId(), organization.getId());
        throw new BadRequestException("User account email belongs to a different organization.");
      }

      handleSuccessfulLogin(user.getId()); // Update last login, reset locks

      if (!user.isEnabled()) {
        log.warn("Re-enabling disabled user '{}' (ID: {}) upon successful SAML login.", user.getUsername(), user.getId());
        user.setEnabled(true);
        userRepository.save(user);
        auditEventService.logEvent(AuditEventType.USER_ENABLED,
                String.format("User account '%s' automatically re-enabled via SAML login", user.getUsername()),
                "SAML_JIT", "SUCCESS",
                "USER", user.getId().toString(), organization.getId(),
                "Registration ID: " + registrationId);
      }
      // TODO: Consider updating roles based on SAML group attributes?
      return user;
    } else {
      // --- User Not Found - Create New User ---
      log.info("No existing user found for email '{}'. Creating new user via SAML JIT for organization '{}'.",
              processedEmail, organization.getOrgName());

      String baseUsername = generateUsernameFromSource(usernameSource, processedEmail);
      String uniqueUsername = findAvailableUsername(baseUsername);
      String randomPassword = generateTemporaryPassword();
      String encodedPassword = passwordEncoder.encode(randomPassword);
      Role userRole = roleRepository.findByRoleType(RoleType.USER)
              .orElseThrow(() -> new ConfigurationException("Default USER role not configured in the system."));

      User newUser = User.builder()
              .username(uniqueUsername)
              .primaryEmail(processedEmail)
              .password(encodedPassword)
              .organization(organization)
              .enabled(true) // Enable immediately
              .temporaryPassword(false)
              .credentialsNonExpired(true)
              .accountNonExpired(true)
              .accountNonLocked(true)
              .passwordChangedDate(Instant.now())
              .lastLoginDate(Instant.now())
              .build();
      newUser.addRole(userRole);

      User savedUser = userRepository.save(newUser);
      log.info("Created new user '{}' (ID: {}) via SAML JIT for organization '{}'.",
              savedUser.getUsername(), savedUser.getId(), organization.getOrgName());

      auditEventService.logEvent(
              AuditEventType.USER_CREATED,
              String.format("User '%s' created via SAML JIT provisioning", savedUser.getUsername()),
              "SAML_JIT_" + registrationId, "SUCCESS",
              "USER", savedUser.getId().toString(),
              organization.getId(),
              "Email: " + processedEmail + ", Role: USER"
      );
      return savedUser;
    }
  }


  // --- Account Status Handling ---

  /**
   * Handles actions needed upon a successful user login.
   * Resets failed login attempt counter, ensures account is unlocked, and updates the last login timestamp.
   *
   * @param userId UUID of the user who successfully logged in.
   */
  @Transactional // Modifies user state
  public void handleSuccessfulLogin(UUID userId) {
    log.debug("Handling successful login procedures for user ID: {}", userId);
    userRepository.findById(userId).ifPresentOrElse(user -> {
      boolean needsUpdate = false;
      // Reset failed attempts and unlock if currently locked (e.g., lock expired just before login)
      if (user.getFailedLoginAttempts() > 0 || !user.isAccountNonLocked()) {
        log.info("Resetting failed login attempts ({}) and ensuring account is unlocked for user '{}' (ID: {}) on successful login.",
                user.getFailedLoginAttempts(), user.getUsername(), userId);
        user.setFailedLoginAttempts(0);
        user.setAccountNonLocked(true);
        user.setLockTime(null);
        needsUpdate = true;
      }

      // Update last login time
      Instant now = Instant.now();
      // Update if last login is null or different from current time (to avoid unnecessary writes on rapid logins)
      if (user.getLastLoginDate() == null || !now.equals(user.getLastLoginDate())) {
        log.debug("Updating last login time for user '{}' (ID: {}) to {}", user.getUsername(), userId, now);
        user.setLastLoginDate(now);
        needsUpdate = true;
      }

      if (needsUpdate) {
        userRepository.save(user); // Save changes
      } else {
        log.trace("No status updates needed on successful login for user ID: {}", userId);
      }
    }, () -> log.error("User not found (ID: {}) during successful login handling!", userId)); // Should not happen if called after successful auth
  }


  /**
   * Handles a failed login attempt for a given username or email.
   * Increments the failed attempt counter and locks the account if the maximum attempts are exceeded.
   * Sends notification if account gets locked.
   *
   * @param usernameOrEmail The username or email used in the failed login attempt.
   */
  @Transactional // Modifies user state
  public void handleFailedLoginAttempt(String usernameOrEmail) {
    log.warn("Handling failed login attempt for username/email: {}", usernameOrEmail);

    userRepository.findByUsernameIgnoreCase(usernameOrEmail)
            .or(() -> userRepository.findByPrimaryEmailIgnoreCase(usernameOrEmail))
            .ifPresentOrElse(user -> {
              // Check if account is already locked and lock hasn't expired
              if (!user.isAccountNonLocked() && user.getLockTime() != null && Instant.now().isBefore(user.getLockTime())) {
                log.warn("Failed login attempt for already locked user '{}' (ID: {}). Lock active until {}.",
                        user.getUsername(), user.getId(), user.getLockTime());
                // Do not increment counter further while locked
                return;
              }

              // If lock expired, reset attempts before incrementing
              if (!user.isAccountNonLocked() && (user.getLockTime() == null || Instant.now().isAfter(user.getLockTime()))) {
                log.info("Resetting expired lock and failed attempts count for user '{}' before processing new failed attempt.", user.getUsername());
                user.setFailedLoginAttempts(0);
                user.setAccountNonLocked(true); // Ensure it's considered unlocked before incrementing below
                user.setLockTime(null);
                // Need to save this state change if we return early, but we'll save after incrementing anyway
              }

              // Increment failed attempts
              int attempts = user.getFailedLoginAttempts() + 1;
              user.setFailedLoginAttempts(attempts);
              log.warn("Failed login attempt {}/{} recorded for user '{}' (ID: {})",
                      attempts, maxFailedAttempts, user.getUsername(), user.getId());

              // Check if max attempts reached
              if (attempts >= maxFailedAttempts) {
                Instant lockExpiry = (lockDurationMinutes > 0)
                        ? Instant.now().plus(lockDurationMinutes, ChronoUnit.MINUTES)
                        : null; // Lock indefinitely if duration is 0 or less? Policy decision. Treat as permanent lock if null.

                user.setAccountNonLocked(false);
                user.setLockTime(lockExpiry);
                log.warn("ACCOUNT LOCKED for user '{}' (ID: {}). Max failed attempts ({}) reached. Locked until: {}",
                        user.getUsername(), user.getId(), maxFailedAttempts, (lockExpiry != null ? lockExpiry : "Indefinitely"));

                // Log audit event for locking
                auditEventService.logEvent(AuditEventType.ACCOUNT_LOCKED,
                        String.format("User account '%s' locked due to %d failed login attempts", user.getUsername(), maxFailedAttempts),
                        user.getUsername(), // Actor is the user attempting login
                        "SUCCESS", // Status of the locking action itself
                        "USER_ACCOUNT", user.getId().toString(), // Target user
                        user.getOrganization() != null ? user.getOrganization().getId() : null,
                        lockExpiry != null ? "Locked until: " + lockExpiry : "Locked indefinitely");

                // Send notification
                notificationService.sendAccountLockedEmail(user);
              }
              userRepository.save(user); // Save updated attempts/lock status

            }, () -> log.warn("Failed login attempt for non-existent username/email: {}. No action taken.", usernameOrEmail));
  }

  /**
   * Enables a user account (sets enabled=true). Typically called after email verification.
   * Logs an audit event.
   *
   * @param userId UUID of the user to enable.
   * @throws ResourceNotFoundException if the user doesn't exist.
   */
  @Transactional
  public void enableAccount(UUID userId) {
    log.info("Attempting to enable account for user ID: {}", userId);
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.USER_NOT_FOUND_ID, userId)));

    if (user.isEnabled()) {
      log.warn("Account enable requested for already enabled user '{}' (ID: {}). No change made.", user.getUsername(), userId);
      // Optionally log audit event for the attempt? Maybe not necessary.
      return; // No action needed
    }

    user.setEnabled(true);
    userRepository.save(user); // Save the change
    log.info("Account enabled successfully for user '{}' (ID: {})", user.getUsername(), userId);

    // Log audit event
    auditEventService.logEvent(
            AuditEventType.USER_ENABLED,
            String.format("User account '%s' enabled", user.getUsername()),
            "SYSTEM/VERIFICATION", // Actor is system process or verification flow
            "SUCCESS",
            "USER", userId.toString(), // Target user
            user.getOrganization() != null ? user.getOrganization().getId() : null,
            "Account enabled, typically post-verification." // Details
    );
  }


  /**
   * Updates a user's password hash and resets relevant flags (temporaryPassword=false, credentialsNonExpired=true).
   * Logs an audit event for the password change.
   *
   * @param userId             UUID of the user whose password is being changed.
   * @param newEncodedPassword The new, securely encoded password hash.
   */
  @Transactional // Ensure flags and password update atomically
  public void updatePasswordAndFlags(UUID userId, String newEncodedPassword) {
    log.debug("Updating password and flags for user ID: {}", userId);
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.USER_NOT_FOUND_ID, userId))); // Should generally exist if called from reset/update flow

    Instant now = Instant.now();
    // Use repository method for potentially optimized update
    userRepository.updateUserPassword(userId, newEncodedPassword, now);
    log.info("Password updated successfully for user '{}' (ID: {}). Temporary flag cleared.", user.getUsername(), userId);

    // Log audit event
    auditEventService.logEvent(
            AuditEventType.PASSWORD_UPDATED, // More specific than RESET_SUCCESS if user initiated change
            String.format("Password changed for user '%s'", user.getUsername()),
            user.getUsername(), // Actor is the user themselves (or system if admin reset) - TODO: differentiate?
            "SUCCESS",
            "USER_CREDENTIALS", userId.toString(),
            user.getOrganization() != null ? user.getOrganization().getId() : null,
            "Password changed. Temporary flag set to false."
    );
  }


  // --- Private Helper Methods ---

  /**
   * Performs authorization checks for user creation requests.
   * Rules: SUPER can create any non-SUPER user. ADMIN can create ADMIN/USER in their own org.
   */
  private void performCreateUserAuthorization(String actor, UUID actorOrgId, Set<RoleType> actorRoles, Organization targetOrg, RoleType requestedRole) {
    log.debug("Performing create user authorization: Actor='{}', ActorOrg='{}', ActorRoles={}, TargetOrg='{}', RequestedRole={}",
            actor, actorOrgId, actorRoles, targetOrg.getId(), requestedRole);

    boolean isActorSuper = actorRoles.contains(RoleType.SUPER);
    boolean isActorAdmin = actorRoles.contains(RoleType.ADMIN);

    // Rule 1: Cannot assign SUPER role via API
    if (requestedRole == RoleType.SUPER) {
      log.warn("AuthZ failed: Actor '{}' attempted to assign SUPER role.", actor);
      throw new OperationNotAllowedException(ApiErrorMessages.INVALID_ROLE_ASSIGNMENT + " Cannot assign SUPER role.");
    }

    // Rule 2: Only SUPER users can create users in the Super Organization
    if (targetOrg.isSuperOrg() && !isActorSuper) {
      log.warn("AuthZ failed: Non-SUPER actor '{}' attempted to create user in Super Org.", actor);
      throw new AccessDeniedException("Only Super Users can create users in the Super Organization.");
    }

    // Rule 3: If actor is not SUPER, they must be ADMIN of the target organization
    if (!isActorSuper) {
      if (!isActorAdmin) {
        log.warn("AuthZ failed: Actor '{}' is not ADMIN or SUPER.", actor);
        throw new AccessDeniedException("User requires ADMIN or SUPER role to create users.");
      }
      // Actor is ADMIN, check if they belong to the target organization
      if (!Objects.equals(targetOrg.getId(), actorOrgId)) {
        log.warn("AuthZ failed: Admin actor '{}' (Org: {}) attempted to create user in different Org ({}).",
                actor, actorOrgId, targetOrg.getId());
        throw new AccessDeniedException("Administrators can only create users within their own organization.");
      }
    }
    // If SUPER user, or ADMIN of the target org, authorization passes.
    log.debug("Create user authorization passed for actor '{}'.", actor);
  }

  /**
   * Validates user creation request data: username/email uniqueness and email domain constraints.
   */
  private void validateUserCreationRequest(CreateUserRequest request, Organization targetOrg) {
    log.debug("Validating user creation request for username '{}', email '{}'", request.getUsername(), request.getPrimaryEmail());
    // Check Username uniqueness
    if (userRepository.existsByUsernameIgnoreCase(request.getUsername().trim())) {
      log.warn("Validation failed: Username '{}' already exists.", request.getUsername());
      throw new ConflictException(String.format(ApiErrorMessages.USERNAME_ALREADY_EXISTS, request.getUsername()));
    }
    // Check Primary Email uniqueness
    String primaryEmailLower = request.getPrimaryEmail().toLowerCase().trim();
    if (userRepository.existsByPrimaryEmailIgnoreCase(primaryEmailLower)) {
      log.warn("Validation failed: Primary email '{}' already exists.", request.getPrimaryEmail());
      throw new ConflictException(String.format(ApiErrorMessages.EMAIL_ALREADY_EXISTS, request.getPrimaryEmail()));
    }
    // Validate Primary Email Domain
    validateEmailDomain(primaryEmailLower, targetOrg.getOrgDomain());

    // Validate Secondary Email Domain (if provided)
    if (StringUtils.hasText(request.getSecondaryEmail())) {
      validateSecondaryEmailDomain(request.getSecondaryEmail().toLowerCase().trim(), targetOrg.getId());
    }
    log.debug("User creation request validation passed.");
  }

  /**
   * Validates that the domain of a primary email matches the expected organization domain.
   */
  private void validateEmailDomain(String email, String expectedDomain) {
    String emailDomain = getDomainFromEmail(email);
    if (emailDomain == null || !expectedDomain.equalsIgnoreCase(emailDomain)) {
      log.warn("Validation failed: Email domain '{}' does not match expected organization domain '{}'.", emailDomain, expectedDomain);
      throw new BadRequestException(String.format(ApiErrorMessages.INVALID_EMAIL_DOMAIN, expectedDomain));
    }
    log.trace("Primary email domain validation passed for email '{}' against domain '{}'", email, expectedDomain);
  }

  /**
   * Validates that a secondary email's domain does not belong to another registered organization.
   */
  private void validateSecondaryEmailDomain(String secondaryEmail, UUID primaryOrgId) {
    String domain = getDomainFromEmail(secondaryEmail);
    if (domain == null) {
      // Should be caught by @Email validation on DTO, but double-check
      log.warn("Validation failed: Invalid secondary email format '{}'.", secondaryEmail);
      throw new BadRequestException("Invalid secondary email format provided.");
    }
    // Check if any *other* organization exists with this domain
    organizationRepository.findByOrgDomainIgnoreCase(domain).ifPresent(conflictingOrg -> {
      if (!Objects.equals(conflictingOrg.getId(), primaryOrgId)) {
        log.warn("Validation failed: Secondary email domain '{}' belongs to another organization (ID: {}).", domain, conflictingOrg.getId());
        throw new ConflictException(String.format(ApiErrorMessages.INVALID_SECONDARY_EMAIL_DOMAIN, domain));
      }
      log.trace("Secondary email domain '{}' matches primary org domain or is not registered to another org.", domain);
    });
    log.trace("Secondary email domain validation passed for email '{}'", secondaryEmail);
  }

  /**
   * Extracts the domain part from an email address.
   * Returns null if the email format is invalid.
   */
  private String getDomainFromEmail(String email) {
    if (!StringUtils.hasText(email)) {
      return null;
    }
    int atIndex = email.lastIndexOf('@');
    // Ensure '@' exists and is not the last character
    if (atIndex == -1 || atIndex == email.length() - 1) {
      return null;
    }
    return email.substring(atIndex + 1);
  }

  /**
   * Generates a secure temporary password meeting basic complexity requirements.
   * Ensures at least one lowercase, one uppercase, one digit, and one special character.
   *
   * @return A randomly generated temporary password string.
   */
  private String generateTemporaryPassword() {
    StringBuilder sb = new StringBuilder(TEMP_PASSWORD_LENGTH);
    // Ensure minimum complexity by including one of each required type first
    sb.append(PASSWORD_LOWER.charAt(secureRandom.nextInt(PASSWORD_LOWER.length())));
    sb.append(PASSWORD_UPPER.charAt(secureRandom.nextInt(PASSWORD_UPPER.length())));
    sb.append(PASSWORD_DIGITS.charAt(secureRandom.nextInt(PASSWORD_DIGITS.length())));
    sb.append(PASSWORD_SPECIAL.charAt(secureRandom.nextInt(PASSWORD_SPECIAL.length())));

    // Fill the rest of the password length with random characters from the allowed set
    for (int i = 4; i < TEMP_PASSWORD_LENGTH; i++) {
      sb.append(PASSWORD_CHARS.charAt(secureRandom.nextInt(PASSWORD_CHARS.length())));
    }

    // Shuffle the generated password characters to avoid predictable patterns (like SPECIAL always being 4th)
    char[] chars = sb.toString().toCharArray();
    // Fisher-Yates shuffle algorithm
    for (int i = chars.length - 1; i > 0; i--) {
      int j = secureRandom.nextInt(i + 1);
      char temp = chars[i];
      chars[i] = chars[j];
      chars[j] = temp;
    }
    log.debug("Generated temporary password (length {})", TEMP_PASSWORD_LENGTH);
    return new String(chars);
  }

  /**
   * Generates a potential username from a source string (like email prefix, NameID, preferred_username).
   * Normalizes the string to lowercase and replaces invalid characters.
   */
  private String generateUsernameFromSource(String usernameSource, String email) {
    String potentialUsername = "";
    // Prefer usernameSource if it looks valid (e.g., not an email itself)
    if (StringUtils.hasText(usernameSource) && !usernameSource.contains("@")) {
      potentialUsername = usernameSource;
    } else if (StringUtils.hasText(email)) {
      // Fallback to email prefix if usernameSource is unusable
      potentialUsername = email.split("@")[0];
    } else {
      // Very unlikely fallback - generate random if both are bad?
      potentialUsername = "user" + secureRandom.nextInt(10000);
      log.warn("Could not derive username from source ('{}') or email ('{}'). Using random '{}'.", usernameSource, email, potentialUsername);
    }

    // Sanitize and normalize
    return potentialUsername
            .toLowerCase()
            .replaceAll("[^a-z0-9_.-]", "_") // Replace invalid chars with underscore
            .replaceAll("_+", "_"); // Collapse multiple underscores
  }


  /**
   * Finds an available username based on a base username, appending numbers if necessary to avoid conflicts.
   *
   * @param baseUsername The desired base username.
   * @return A unique username string.
   * @throws ConfigurationException if a unique username cannot be generated after max attempts.
   */
  private String findAvailableUsername(String baseUsername) {
    if (!StringUtils.hasText(baseUsername)) {
      baseUsername = "user"; // Default base if input is empty
    }
    // Ensure base doesn't exceed max length minus potential counter digits
    int maxBaseLength = 50 - 4; // Max username 50, leave space for e.g., "_999"
    if (baseUsername.length() > maxBaseLength) {
      baseUsername = baseUsername.substring(0, maxBaseLength);
    }

    String uniqueUsername = baseUsername;
    int counter = 1;
    int maxAttempts = 1000; // Limit attempts to prevent infinite loops

    // Check if the base username is available, if not, append counter
    while (userRepository.existsByUsernameIgnoreCase(uniqueUsername) && counter <= maxAttempts) {
      uniqueUsername = baseUsername + counter; // Simple append
      // Or use baseUsername + "_" + counter;
      counter++;
    }

    if (counter > maxAttempts) {
      log.error("Could not generate a unique username based on '{}' after {} attempts.", baseUsername, maxAttempts);
      // This indicates a high density of similar usernames or a logic issue.
      throw new ConfigurationException("Unable to generate a unique username. Please try a different base or contact support.");
    }
    if (counter > 1) { // Log if we had to append a number
      log.warn("Username collision occurred for base '{}'. Generated unique username: '{}'", baseUsername, uniqueUsername);
    } else {
      log.debug("Base username '{}' is available.", baseUsername);
    }
    return uniqueUsername;
  }

  /**
   * Authorizes access to a specific user's data based on the actor's identity and roles.
   * Allows access if actor is SUPER, ADMIN of the target user's org, or the user themselves.
   * Throws AccessDeniedException if not authorized.
   */
  private void authorizeUserAccess(String actorUsername, UUID actorOrgId, Set<RoleType> actorRoles, User targetUser, String action) {
    boolean isSuper = actorRoles.contains(RoleType.SUPER);
    boolean isAdmin = actorRoles.contains(RoleType.ADMIN);
    boolean isSelf = targetUser.getUsername().equalsIgnoreCase(actorUsername);
    UUID targetUserOrgId = (targetUser.getOrganization() != null) ? targetUser.getOrganization().getId() : null;
    boolean isAdminOfTargetOrg = isAdmin && Objects.equals(actorOrgId, targetUserOrgId);

    if (isSuper || isSelf || isAdminOfTargetOrg) {
      log.trace("Authorization successful for actor '{}' to {} user '{}'", actorUsername, action, targetUser.getUsername());
      return; // Authorized
    }

    // If none of the above conditions met, deny access
    log.warn("Authorization failed: Actor '{}' (Org: {}, Roles: {}) cannot {} user '{}' (Org: {}).",
            actorUsername, actorOrgId, actorRoles, action, targetUser.getUsername(), targetUserOrgId);
    throw new AccessDeniedException("User does not have permission to " + action + " this user's profile.");
  }

} // End of UserService class