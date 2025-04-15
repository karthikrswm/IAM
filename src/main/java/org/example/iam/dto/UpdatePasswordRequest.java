// File: src/main/java/org/example/iam/dto/UpdatePasswordRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.constant.ApiErrorMessages; // For cross-field validation message

/**
 * Data Transfer Object (DTO) representing the request payload for a user to update their own password.
 * This is typically used in a "change password" feature within user profile settings.
 * Requires the user's current password for verification, along with the new password and its confirmation.
 * Includes validation annotations, including cross-field validation for password confirmation.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for an authenticated user to change their own password")
public class UpdatePasswordRequest {

  @NotBlank(message = "Current password cannot be blank.")
  @Schema(description = "The user's current, existing password for verification.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "OldStr0ngP@ssw0rd", format = "password")
  private String currentPassword;

  @NotBlank(message = "New password cannot be blank.")
  @Size(min = 12, max = 100, message = "New password must be between 12 and 100 characters.")
  // Optional: Add complexity pattern if desired for client-side hint, backend enforces regardless.
  // @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()\\-_=+]).{12,}$", message = ApiErrorMessages.INVALID_PASSWORD_FORMAT)
  @Schema(description = "The desired new password. Must meet complexity requirements and be different from the current password.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "NewerStr0ngP@ssw0rd!", format = "password", minLength = 12, maxLength = 100)
  private String newPassword;

  @NotBlank(message = "Password confirmation cannot be blank.")
  @Schema(description = "Confirmation of the new password. Must exactly match the 'newPassword' field.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "NewerStr0ngP@ssw0rd!", format = "password")
  private String confirmNewPassword;

  /**
   * Custom validation method using {@link AssertTrue} to ensure the new password fields match.
   * Handles null inputs gracefully to let {@code @NotBlank} handle those first.
   *
   * @return {@code true} if passwords match or if fields are null/blank (allowing other validators to handle), {@code false} otherwise.
   */
  @AssertTrue(message = ApiErrorMessages.PASSWORD_MISMATCH)
  @Schema(hidden = true) // Hide this internal validation logic from the API schema
  public boolean isPasswordConfirmed() {
    // Avoid triggering this validation if @NotBlank already failed
    if (newPassword == null || confirmNewPassword == null) {
      return true;
    }
    return newPassword.equals(confirmNewPassword);
  }
}