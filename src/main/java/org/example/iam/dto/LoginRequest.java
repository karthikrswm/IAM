// File: src/main/java/org/example/iam/dto/LoginRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object (DTO) representing the request payload for user login
 * using username/email and password (typically for the JWT authentication flow).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for user authentication via username/email and password")
public class LoginRequest {

  @NotBlank(message = "Username or email cannot be blank.")
  @Schema(description = "The user's registered username or primary email address.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "j.doe or j.doe@examplecorp.com")
  private String usernameOrEmail;

  @NotBlank(message = "Password cannot be blank.")
  // Consider adding @Size if there are min/max password length policies enforced elsewhere,
  // but validation here might be redundant as backend handles actual auth check.
  // @Size(min = 12, max = 100, message = "Password length check (informational)")
  @Schema(description = "The user's current password.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "Str0ngP@ssw0rd!", format = "password")
  private String password;
}