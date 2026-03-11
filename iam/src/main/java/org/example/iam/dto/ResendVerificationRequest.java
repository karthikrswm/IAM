// File: src/main/java/org/example/iam/dto/ResendVerificationRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object (DTO) representing the request payload for resending an email
 * verification link to a user. Contains the primary email address of the target user.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload to trigger resending the email verification link")
public class ResendVerificationRequest {

  @NotBlank(message = "Email cannot be blank.")
  @Email(message = "Email must be a valid email address format.")
  @Size(max = 100, message = "Email cannot exceed 100 characters.")
  @Schema(description = "The primary email address of the user who needs the verification email resent.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "unverified.user@examplecorp.com", maxLength = 100)
  private String email;
}