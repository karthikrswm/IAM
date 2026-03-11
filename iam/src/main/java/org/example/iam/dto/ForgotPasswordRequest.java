// File: src/main/java/org/example/iam/dto/ForgotPasswordRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object (DTO) representing the request payload for initiating the
 * "forgot password" process. Contains the primary email address associated with the user account.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload to initiate the password reset process for a user")
public class ForgotPasswordRequest {

  @NotBlank(message = "Email cannot be blank.")
  @Email(message = "Email must be a valid email address format.")
  @Size(max = 100, message = "Email cannot exceed 100 characters.")
  @Schema(description = "The primary email address associated with the user account requiring a password reset.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "user@examplecorp.com", maxLength = 100)
  private String email;
}