// File: src/main/java/org/example/iam/dto/UpdateOrgRequest.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.constant.LoginType;

/**
 * Data Transfer Object (DTO) representing the request payload for updating an existing Organization's
 * mutable details.
 * <p>
 * Currently allows updating the organization's name and the login type required for its users.
 * Changing the organization's domain is generally a more complex operation and is not permitted
 * via this request. SAML/OAuth2 configurations are managed via separate dedicated endpoints.
 * </p>
 * Used by Super Users or Administrators of the target organization.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for updating mutable details of an existing Organization (e.g., name, login type)")
public class UpdateOrgRequest {

  @NotBlank(message = "Organization name cannot be blank.")
  @Size(min = 2, max = 100, message = "Organization name must be between 2 and 100 characters.")
  @Schema(description = "The updated name for the organization. Must be unique across the system if changed.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "Example Corporation Ltd.", minLength = 2, maxLength = 100)
  private String orgName;

  @NotNull(message = "Login type must be specified.")
  @Schema(description = "The updated required login mechanism for regular users of this organization. Changing this may affect user login capabilities and require corresponding SAML/OAuth2 configuration updates if applicable.",
          requiredMode = Schema.RequiredMode.REQUIRED, example = "SAML", implementation = LoginType.class)
  private LoginType loginType; // Enum: JWT, SAML, OAUTH2

  // Note: orgDomain is intentionally excluded from this update DTO.
  // Changing an organization's primary domain often has significant implications
  // (e.g., requires user email updates, SSO config changes) and should typically be
  // handled through a more deliberate process or dedicated API if allowed at all.
}