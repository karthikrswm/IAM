// File: src/main/java/org/example/iam/dto/UserResponse.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.constant.RoleType;
import org.example.iam.entity.Role;
import org.example.iam.entity.User;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Data Transfer Object (DTO) representing the standard response format for user details.
 * Returned by API endpoints that retrieve or manage user accounts. Includes core user
 * information, status flags, role assignments, organization details, and audit metadata.
 */
@Data // Generates getters, setters, toString, equals, hashCode, required args constructor
@Builder // Enables the builder pattern
@NoArgsConstructor // Needed for Jackson/JPA
@AllArgsConstructor // Generates all-args constructor
@Schema(description = "Standard response payload containing details about a User account")
public class UserResponse {

  @Schema(description = "Unique identifier (UUID) of the user account.",
          example = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
  private UUID id;

  @Schema(description = "Unique username associated with the account.", example = "j.doe")
  private String username;

  @Schema(description = "User's primary email address (used for login and notifications).",
          example = "j.doe@examplecorp.com")
  private String primaryEmail;

  @Schema(description = "User's optional secondary email address.",
          nullable = true, example = "john.doe.personal@mail.com")
  private String secondaryEmail;

  @Schema(description = "User's optional phone number.",
          nullable = true, example = "+1-555-123-4567")
  private String phoneNumber;

  @Schema(description = "Basic information about the organization the user belongs to.")
  private OrgBasicInfo organization; // Nested DTO for basic Org info

  @Schema(description = "Set of roles assigned to the user.", example = "[\"ADMIN\", \"USER\"]")
  private Set<RoleType> roles; // Use RoleType enum for clarity

  // --- Account Status Fields ---
  @Schema(description = "Indicates if the user's account is currently enabled (verified and active).", example = "true")
  private boolean enabled; // From user.isEnabled()

  @Schema(description = "Indicates if the user's account is currently locked (e.g., due to failed login attempts).", example = "false")
  private boolean locked; // Derived from !user.isAccountNonLocked()

  @Schema(description = "Indicates if the user's credentials (password) have expired and require reset.", example = "false")
  private boolean credentialsExpired; // Derived from !user.isCredentialsNonExpired()

  @Schema(description = "Indicates if the user logged in with a temporary password and must change it.", example = "false")
  private boolean temporaryPassword; // From user.isTemporaryPassword() - relevant for profile/initial login context


  // --- Audit & Timing Fields ---
  @Schema(description = "Timestamp when the user account was created (ISO 8601 format in UTC).",
          example = "2025-02-10T11:00:00Z")
  private Instant createdDate;

  @Schema(description = "Timestamp when the user account was last modified (ISO 8601 format in UTC).",
          example = "2025-04-10T12:30:00Z")
  private Instant lastModifiedDate;

  @Schema(description = "Identifier of the user or system that created this account.",
          example = "admin@examplecorp.com")
  private String createdBy;

  @Schema(description = "Identifier of the user or system that last modified this account.",
          example = "SYSTEM")
  private String lastModifiedBy;

  @Schema(description = "Timestamp of the user's last successful login (ISO 8601 format in UTC).",
          nullable = true, example = "2025-04-14T10:05:00Z")
  private Instant lastLoginDate;

  @Schema(description = "Timestamp when the user's password was last changed (ISO 8601 format in UTC).",
          example = "2025-03-20T14:00:00Z")
  private Instant passwordChangedDate;


  /**
   * Static factory method to create a UserResponse DTO from a User entity.
   * Populates the DTO fields, including nested organization info and derived status flags.
   * Handles null input gracefully.
   *
   * @param user The {@link User} entity.
   * @return A corresponding {@link UserResponse}, or null if the input entity is null.
   */
  public static UserResponse fromEntity(User user) {
    if (user == null) {
      return null;
    }

    // Create nested OrgBasicInfo DTO if organization exists
    OrgBasicInfo orgInfo = null;
    if (user.getOrganization() != null) {
      orgInfo = OrgBasicInfo.builder()
              .id(user.getOrganization().getId())
              .orgName(user.getOrganization().getOrgName())
              .orgDomain(user.getOrganization().getOrgDomain())
              .build();
    }

    // Build the UserResponse DTO
    return UserResponse.builder()
            .id(user.getId())
            .username(user.getUsername())
            .primaryEmail(user.getPrimaryEmail())
            .secondaryEmail(user.getSecondaryEmail())
            .phoneNumber(user.getPhoneNumber())
            .organization(orgInfo)
            // Map Role entities to RoleType enums
            .roles(user.getRoles().stream()
                    .map(Role::getRoleType) // Assumes Role entity has getRoleType() via Lombok
                    .collect(Collectors.toSet()))
            // Map status fields directly or derive them
            .enabled(user.isEnabled()) // From UserDetails interface impl
            .locked(!user.isAccountNonLocked()) // Derived: locked is the inverse of non-locked
            .credentialsExpired(!user.isCredentialsNonExpired()) // Derived: expired is inverse of non-expired
            .temporaryPassword(user.isTemporaryPassword())
            // Audit and timing fields
            .createdDate(user.getCreatedDate()) // Inherited from Auditable
            .lastModifiedDate(user.getLastModifiedDate()) // Inherited from Auditable
            .createdBy(user.getCreatedBy()) // Inherited from Auditable
            .lastModifiedBy(user.getLastModifiedBy()) // Inherited from Auditable
            .lastLoginDate(user.getLastLoginDate())
            .passwordChangedDate(user.getPasswordChangedDate())
            .build();
  }

  /**
   * Nested static DTO containing basic identifying information about an Organization.
   * Used within the UserResponse DTO.
   */
  @Data // Generates getters, setters, etc. for the nested class
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  @Schema(description = "Basic identifying information about the user's organization")
  public static class OrgBasicInfo {

    @Schema(description = "Unique identifier (UUID) of the organization.",
            example = "f0e9d8c7-b6a5-4321-fedc-ba9876543210")
    private UUID id;

    @Schema(description = "Registered name of the organization.", example = "Example Corp")
    private String orgName;

    @Schema(description = "Registered primary internet domain of the organization.", example = "examplecorp.com")
    private String orgDomain;
  }
}