// File: src/main/java/org/example/iam/dto/ResetPasswordRequest.java
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
 * Data Transfer Object (DTO) representing the request payload for resetting a user's password
 * using a token received via the "forgot password" process.
 * Includes the token, the new password, and a confirmation of the new password.
 * Contains validation annotations, including cross-field validation for password confirmation.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload to reset a user's password using a valid reset token")
public class ResetPasswordRequest {

  @NotBlank(message = "Token cannot be blank.")
  @Schema(description = "The password reset token received by the user (usually via email link).",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "a1b2c3d4-e5f6-...")
  private String token;

  @NotBlank(message = "New password cannot be blank.")
  // Enforce minimum length, maximum is useful against denial-of-service via large inputs.
  @Size(min = 12, max = 100, message = "New password must be between 12 and 100 characters.")
  // Optional: Add @Pattern for complexity rules if frontend doesn't enforce strictly,
  // though backend should re-validate anyway. Use constant if defined.
  // @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()\\-_=+]).{12,}$",
  //          message = ApiErrorMessages.INVALID_PASSWORD_FORMAT)
  @Schema(description = "The desired new password. Must meet the system's complexity requirements (e.g., length, character types).",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "NewResetP@ssw0rd!", format = "password", minLength = 12, maxLength = 100)
  private String newPassword;

  @NotBlank(message = "Password confirmation cannot be blank.")
  // No need for @Size/@Pattern here, just needs to match newPassword
  @Schema(description = "Confirmation of the new password. Must exactly match the 'newPassword' field.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "NewResetP@ssw0rd!", format = "password")
  private String confirmNewPassword;

  /**
   * Custom validation method to ensure the new password and its confirmation match.
   * Triggered by the {@link AssertTrue} annotation.
   * Handles null cases gracefully, allowing {@code @NotBlank} to handle them first.
   *
   * @return {@code true} if passwords match or if either field is null (letting other validators handle null/blank),
   * {@code false} otherwise.
   */
  @AssertTrue(message = ApiErrorMessages.PASSWORD_MISMATCH) // Use constant for error message
  @Schema(hidden = true) // Hide this validation logic method from Swagger schema
  public boolean isPasswordConfirmed() {
    // If either field fails @NotBlank, don't trigger this assert - avoid redundant errors.
    if (newPassword == null || confirmNewPassword == null) {
      return true;
    }
    // Perform the actual comparison.
    return newPassword.equals(confirmNewPassword);
  }
}