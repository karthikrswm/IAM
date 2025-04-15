// File: src/main/java/org/example/iam/dto/CreateOrgRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.constant.LoginType;

/**
 * Data Transfer Object (DTO) representing the request payload for creating a new Organization.
 * Used typically by Super Users via the Organization Management API.
 * Includes validation annotations to ensure data integrity and Swagger annotations for API documentation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload containing details required to create a new Organization (tenant)")
public class CreateOrgRequest {

  @NotBlank(message = "Organization name cannot be blank.")
  @Size(min = 2, max = 100, message = "Organization name must be between 2 and 100 characters.")
  @Schema(description = "The desired name for the new organization. Must be unique across the system.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "Example Corp", minLength = 2, maxLength = 100)
  private String orgName;

  @NotBlank(message = "Organization domain cannot be blank.")
  @Size(min = 3, max = 100, message = "Organization domain must be between 3 and 100 characters.")
  // Regex for basic domain validation (doesn't guarantee existence, just format)
  @Pattern(regexp = "^(?=.{1,253}\\.?$)([a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$",
          message = "Invalid domain format. Example: 'examplecorp.com'")
  @Schema(description = "The primary internet domain associated with the organization. Used for email validation and potentially SSO configuration. Must be unique.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "examplecorp.com", minLength = 3, maxLength = 100)
  private String orgDomain;

  @NotNull(message = "Login type must be specified.")
  @Schema(description = "The required login mechanism for regular users belonging to this organization.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "JWT", implementation = LoginType.class)
  private LoginType loginType; // Enum: JWT, SAML, OAUTH2
}