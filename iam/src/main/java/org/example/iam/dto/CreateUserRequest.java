// File: src/main/java/org/example/iam/dto/CreateUserRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.constant.RoleType; // Use RoleType enum

import java.util.UUID;

/**
 * Data Transfer Object (DTO) representing the request payload for creating a new User account.
 * Used typically by Administrators or Super Users via the User Management API.
 * Includes validation annotations to ensure data integrity and Swagger annotations for API documentation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload containing details required to create a new User account within an organization")
public class CreateUserRequest {

  @NotBlank(message = "Username cannot be blank.")
  @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters.")
  // Allow letters, numbers, underscore, dot, hyphen. Adjust regex as needed.
  @Pattern(regexp = "^[a-zA-Z0-9_.-]+$", message = "Username can only contain letters, numbers, underscore, dot, and hyphen.")
  @Schema(description = "Unique username for the new account. Must be unique globally.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "j.doe", minLength = 3, maxLength = 50)
  private String username;

  @NotBlank(message = "Primary email cannot be blank.")
  @Email(message = "Primary email must be a valid email address format.")
  @Size(max = 100, message = "Primary email cannot exceed 100 characters.")
  @Schema(description = "User's primary email address. Must be unique globally. The domain part must match the organization's domain.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "j.doe@examplecorp.com", maxLength = 100)
  private String primaryEmail;

  // Optional field: Secondary Email
  @Email(message = "Secondary email must be a valid email address format, if provided.")
  @Size(max = 100, message = "Secondary email cannot exceed 100 characters.")
  @Schema(description = "Optional secondary email address for the user. Cannot use a domain registered to another organization.",
          requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "john.doe.personal@mail.com", maxLength = 100, nullable = true)
  private String secondaryEmail;

  // Optional field: Phone Number
  @Size(max = 20, message = "Phone number cannot exceed 20 characters.")
  // Consider adding @Pattern for specific formats if needed (e.g., E.164)
  // @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid phone number format")
  @Schema(description = "Optional phone number for the user.",
          requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "+1-555-123-4567", maxLength = 20, nullable = true)
  private String phoneNumber;

  @NotNull(message = "Role type must be specified.")
  @Schema(description = "The role to assign to the new user (ADMIN or USER). The SUPER role cannot be assigned via this API.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "ADMIN", implementation = RoleType.class)
  private RoleType roleType; // Enum: ADMIN, USER

  @NotNull(message = "Organization ID must be provided.")
  @Schema(description = "The UUID of the organization this user will belong to.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
  private UUID organizationId; // UUID of the target organization
}