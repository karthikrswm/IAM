// File: src/main/java/org/example/iam/dto/UpdateUserRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object (DTO) representing the request payload for updating a user's profile information.
 * <p>
 * This DTO is primarily intended for updating optional or less sensitive fields, such as the
 * secondary email address and phone number. Core identifiers (username, primary email) and
 * status fields (enabled status, account lock status, roles) are typically managed through
 * different, more specific processes or administrative actions, not via this general profile update.
 * </p>
 * Used by the user themselves or authorized administrators/super users.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for updating mutable user profile details (e.g., secondary email, phone number)")
public class UpdateUserRequest {

  // Note: @Email allows null by default. Validation applies only if a value is provided.
  @Email(message = "Secondary email must be a valid email address format, if provided.")
  @Size(max = 100, message = "Secondary email cannot exceed 100 characters.")
  @Schema(description = "Updated optional secondary email address for the user. If provided, its domain must not belong to another registered organization.",
          requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "user.personal.updated@example.net", nullable = true, maxLength = 100)
  private String secondaryEmail; // Allow null to clear the field

  @Size(max = 20, message = "Phone number cannot exceed 20 characters.")
  // Consider adding @Pattern if a specific phone format (e.g., E.164) is strictly required:
  // @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid phone number format (should be E.164)")
  @Schema(description = "Updated optional phone number for the user.",
          requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "+442071234567", nullable = true, maxLength = 20)
  private String phoneNumber; // Allow null to clear the field

  // Fields like username, primaryEmail, role, enabled status, locked status
  // are intentionally *not* included here as they usually require different
  // update mechanisms or permissions.
}