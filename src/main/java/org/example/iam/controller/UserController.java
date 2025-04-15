// File: src/main/java/org/example/iam/controller/UserController.java
package org.example.iam.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiError;
import org.example.iam.api.ApiSuccessResponse;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.ApiResponseMessages;
import org.example.iam.constant.RoleType;
import org.example.iam.dto.*; // Import necessary DTOs
import org.example.iam.security.SecurityUtils;
import org.example.iam.service.UserService;
import org.springdoc.core.annotations.ParameterObject; // For Pageable Swagger documentation
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

// Removed unused List import
import java.util.Set;
import java.util.UUID;

/**
 * REST Controller for managing User accounts within organizations.
 * Provides endpoints for creating, retrieving, updating, listing, and deleting users,
 * as well as self-service password changes.
 * Requires appropriate authentication and authorization (SUPER, ADMIN, or self).
 */
@RestController
@RequestMapping("/api/v1") // Base path includes /users and /organizations/{orgId}/users
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "Endpoints for managing user accounts")
@SecurityRequirement(name = "bearerAuth") // Indicate JWT Bearer token is generally required
public class UserController {

  private final UserService userService;

  /**
   * Creates a new user within a specified organization.
   * Requires ADMIN role of the target organization or SUPER role.
   * Sends a verification email with a temporary password upon successful creation.
   *
   * @param createUserRequest DTO containing details for the new user.
   * @return ResponseEntity containing ApiResponse<UserResponse> or ApiError.
   */
  @Operation(summary = "Create User",
          description = "Creates a new user account within a specified organization. Requires SUPER role, or ADMIN role of the target organization. Sends verification email.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "201", description = ApiResponseMessages.USER_CREATED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT + " / " + ApiErrorMessages.INVALID_EMAIL_DOMAIN,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED + " / " + ApiErrorMessages.INVALID_ROLE_ASSIGNMENT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "409", description = ApiErrorMessages.USERNAME_ALREADY_EXISTS + " / " + ApiErrorMessages.EMAIL_ALREADY_EXISTS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PostMapping("/users")
  @PreAuthorize("hasAnyRole('ADMIN', 'SUPER')") // Service verifies ADMIN role is for correct org
  public ResponseEntity<ApiSuccessResponse<UserResponse>> createUser(
          @Valid @RequestBody CreateUserRequest createUserRequest) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to create user '{}' in org '{}'",
            actorUsername, actorOrgId, actorRoles, createUserRequest.getUsername(), createUserRequest.getOrganizationId());

    UserResponse createdUser = userService.createUser(createUserRequest, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<UserResponse> response = ApiSuccessResponse.created(createdUser, ApiResponseMessages.USER_CREATED_SUCCESS);
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  /**
   * Retrieves details for a specific user by their ID.
   * Requires authentication. Access allowed for SUPER users, ADMIN of the user's org, or the user themselves.
   *
   * @param userId UUID of the user to retrieve.
   * @return ResponseEntity containing ApiResponse<UserResponse> or ApiError.
   */
  @Operation(summary = "Get User by ID",
          description = "Retrieves details for a specific user. Requires authentication. Access allowed for SUPER users, ADMIN of the user's org, or the user themselves.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.USER_RETRIEVED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.USER_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping("/users/{userId}")
  @PreAuthorize("isAuthenticated()") // Service layer performs fine-grained access check
  public ResponseEntity<ApiSuccessResponse<UserResponse>> getUserById(
          @Parameter(description = "UUID of the user to retrieve", required = true) @PathVariable UUID userId) {

    String actorUsername = SecurityUtils.getCurrentUsername().orElse("UnknownActor");
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to retrieve user ID '{}'",
            actorUsername, actorOrgId, actorRoles, userId);

    UserResponse user = userService.getUserById(userId, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<UserResponse> response = ApiSuccessResponse.ok(user, ApiResponseMessages.USER_RETRIEVED_SUCCESS);
    return ResponseEntity.ok(response);
  }

  /**
   * Updates a user's profile information (currently secondary email and phone number).
   * Requires authentication. Access allowed for SUPER users, ADMIN of the user's org, or the user themselves.
   *
   * @param userId            UUID of the user to update.
   * @param updateUserRequest DTO containing the fields to update.
   * @return ResponseEntity containing ApiResponse<UserResponse> or ApiError.
   */
  @Operation(summary = "Update User Profile",
          description = "Updates mutable profile details for a user (e.g., secondary email, phone number). Access allowed for SUPER users, ADMIN of the user's org, or the user themselves.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.USER_UPDATED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT + " / " + ApiErrorMessages.INVALID_SECONDARY_EMAIL_DOMAIN,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.USER_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "409", description = ApiErrorMessages.INVALID_SECONDARY_EMAIL_DOMAIN, // Domain conflict
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PutMapping("/users/{userId}")
  @PreAuthorize("isAuthenticated()") // Service layer performs fine-grained access check
  public ResponseEntity<ApiSuccessResponse<UserResponse>> updateUser(
          @Parameter(description = "UUID of the user to update", required = true) @PathVariable UUID userId,
          @Valid @RequestBody UpdateUserRequest updateUserRequest) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to update profile for user ID '{}'",
            actorUsername, actorOrgId, actorRoles, userId);

    UserResponse updatedUser = userService.updateUser(userId, updateUserRequest, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<UserResponse> response = ApiSuccessResponse.ok(updatedUser, ApiResponseMessages.USER_UPDATED_SUCCESS);
    return ResponseEntity.ok(response);
  }

  /**
   * Retrieves a paginated list of users belonging to a specific organization.
   * Requires SUPER role or ADMIN role of the target organization.
   * Supports standard Spring Data pagination and sorting parameters.
   *
   * @param orgId    UUID of the organization whose users are to be listed.
   * @param pageable Pagination and sorting information (e.g., ?page=0&size=20&sort=username,asc).
   * @return ResponseEntity containing ApiResponse<Page<UserResponse>> or ApiError.
   */
  @Operation(summary = "Get All Users by Organization",
          description = "Retrieves a paginated list of users for a specific organization. Requires SUPER role or ADMIN role of that organization.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ALL_USERS_RETRIEVED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))), // Schema shows Page<UserResponse> structure
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  // Add parameters for pagination/sorting to Swagger UI using @ParameterObject
  @Parameters({
          @Parameter(name = "page", description = "Page number (0-indexed)", in = ParameterIn.QUERY, schema = @Schema(type = "integer", defaultValue = "0")),
          @Parameter(name = "size", description = "Number of items per page", in = ParameterIn.QUERY, schema = @Schema(type = "integer", defaultValue = "20")),
          @Parameter(name = "sort", description = "Sorting criteria (e.g., 'username,asc' or 'primaryEmail,desc')", in = ParameterIn.QUERY, schema = @Schema(type = "string"))
  })
  @GetMapping("/organizations/{orgId}/users")
  @PreAuthorize("hasAnyRole('SUPER', 'ADMIN')") // Service verifies ADMIN is for correct org
  public ResponseEntity<ApiSuccessResponse<Page<UserResponse>>> getAllUsersByOrganization(
          @Parameter(description = "UUID of the organization", required = true) @PathVariable UUID orgId,
          @ParameterObject Pageable pageable) { // Use @ParameterObject for Pageable

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) listing users for org ID '{}' with pageable: {}",
            actorUsername, actorOrgId, actorRoles, orgId, pageable);

    Page<UserResponse> userPage = userService.getAllUsersByOrganization(orgId, actorUsername, actorOrgId, actorRoles, pageable);

    ApiSuccessResponse<Page<UserResponse>> response = ApiSuccessResponse.ok(userPage, ApiResponseMessages.ALL_USERS_RETRIEVED_SUCCESS);
    return ResponseEntity.ok(response);
  }

  /**
   * Deletes a user account.
   * Requires SUPER role or ADMIN role of the user's organization (Admins cannot delete other Admins).
   * Users cannot delete themselves or Super Users.
   *
   * @param userId UUID of the user to delete.
   * @return ResponseEntity containing ApiResponse<Void> or ApiError.
   */
  @Operation(summary = "Delete User",
          description = "Deletes a user account. Requires SUPER role, or ADMIN role of the user's organization (cannot delete other Admins or self). Cannot delete Super Users.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.USER_DELETED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED + " / " + ApiErrorMessages.OPERATION_NOT_ALLOWED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.USER_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @DeleteMapping("/users/{userId}")
  @PreAuthorize("hasAnyRole('SUPER', 'ADMIN')") // Service layer performs fine-grained checks
  public ResponseEntity<ApiSuccessResponse<Void>> deleteUser(
          @Parameter(description = "UUID of the user to delete", required = true) @PathVariable UUID userId) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.warn("Actor '{}' (Org: {}, Roles: {}) initiating DELETE operation for user ID: {}",
            actorUsername, actorOrgId, actorRoles, userId);

    userService.deleteUser(userId, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(ApiResponseMessages.USER_DELETED_SUCCESS);
    log.info("User ID '{}' successfully deleted by actor '{}'.", userId, actorUsername);
    return ResponseEntity.ok(response);
  }

  /**
   * Allows the currently authenticated user to change their own password.
   * Requires the current password for verification.
   *
   * @param updatePasswordRequest DTO containing current and new password details.
   * @return ResponseEntity containing ApiResponse<Void> or ApiError.
   */
  @Operation(summary = "Change Own Password",
          description = "Allows the currently authenticated user to change their own password by providing the current password and a new password.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.PASSWORD_UPDATED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.PASSWORD_MISMATCH + " or New password is same as old",
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT + " or " + ApiErrorMessages.BAD_CREDENTIALS + " (Invalid current password)",
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PutMapping("/me/password") // Specific path for self-service action
  @PreAuthorize("isAuthenticated()") // User must be logged in
  public ResponseEntity<ApiSuccessResponse<Void>> changeOwnPassword(
          @Valid @RequestBody UpdatePasswordRequest updatePasswordRequest) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    log.info("User '{}' initiating self-service password change.", actorUsername);

    userService.updateUserPassword(updatePasswordRequest, actorUsername);

    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(ApiResponseMessages.PASSWORD_UPDATED_SUCCESS);
    return ResponseEntity.ok(response);
  }
}