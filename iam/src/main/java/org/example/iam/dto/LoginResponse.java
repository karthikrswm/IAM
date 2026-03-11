// File: src/main/java/org/example/iam/dto/LoginResponse.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.entity.User; // For context

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Data Transfer Object (DTO) representing the successful response after a user authenticates
 * via the JWT login flow (username/password).
 * Contains the JWT access token and essential user/session information.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response payload after successful JWT-based user authentication")
public class LoginResponse {

  @Schema(description = "Indicates the type of token issued", example = "Bearer",
          accessMode = Schema.AccessMode.READ_ONLY)
  private final String tokenType = "Bearer"; // Standard type for JWT

  @Schema(description = "Username of the successfully authenticated user", example = "j.doe")
  private String username;

  @Schema(description = "Unique identifier (UUID) of the authenticated user",
          example = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
  private UUID userId;

  @Schema(description = "Unique identifier (UUID) of the organization the user belongs to",
          example = "f0e9d8c7-b6a5-4321-fedc-ba9876543210")
  private UUID organizationId;

  @Schema(description = "The JWT Bearer token used for authenticating subsequent API requests",
          example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ...") // Example structure
  private String accessToken;

  @Schema(description = "Timestamp when the access token expires (ISO 8601 format in UTC)",
          example = "2025-04-15T09:30:00.123Z")
  private Instant expiresAt;

  @Schema(description = "Set of roles assigned to the user (e.g., ROLE_ADMIN, ROLE_USER)",
          example = "[\"ROLE_ADMIN\", \"ROLE_USER\"]")
  private Set<String> roles; // Role names as strings

  @Schema(description = "Flag indicating if the user logged in with a temporary password and must change it upon first use.",
          example = "false")
  private boolean requiresPasswordChange; // True if user.isTemporaryPassword() was true
}