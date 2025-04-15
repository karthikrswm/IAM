// File: src/main/java/org/example/iam/dto/OrgResponse.java
package org.example.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.iam.constant.LoginType;
import org.example.iam.entity.Organization;

import java.time.Instant;
import java.util.UUID;

/**
 * Data Transfer Object (DTO) representing the standard response format for Organization details.
 * Returned by API endpoints that retrieve or manage organizations.
 * Includes core organization properties and audit metadata.
 */
@Data // Generates getters, setters, toString, equals, hashCode, required args constructor
@Builder // Enables the builder pattern for object creation
@NoArgsConstructor // Needed for Jackson/JPA frameworks
@AllArgsConstructor // Generates constructor with all fields
@Schema(description = "Standard response payload containing details about an Organization")
public class OrgResponse {

  @Schema(description = "Unique identifier (UUID) of the organization.",
          example = "f0e9d8c7-b6a5-4321-fedc-ba9876543210")
  private UUID id;

  @Schema(description = "Registered name of the organization.", example = "Example Corp")
  private String orgName;

  @Schema(description = "Registered primary internet domain of the organization.", example = "examplecorp.com")
  private String orgDomain;

  @Schema(description = "The required login mechanism for regular users of this organization.",
          example = "JWT", implementation = LoginType.class)
  private LoginType loginType;

  @Schema(description = "Flag indicating if this is the special 'Super Organization' used for system administration.",
          example = "false")
  private boolean isSuperOrg;

  @Schema(description = "Flag indicating if a SAML 2.0 configuration exists and is potentially enabled for this organization.",
          example = "false")
  private boolean hasSamlConfig; // Derived field

  @Schema(description = "Flag indicating if an OAuth 2.0 configuration exists and is potentially enabled for this organization.",
          example = "true")
  private boolean hasOauth2Config; // Derived field

  // --- Audit Fields ---
  @Schema(description = "Timestamp when the organization was created (ISO 8601 format in UTC).",
          example = "2025-01-15T10:00:00Z")
  private Instant createdDate;

  @Schema(description = "Timestamp when the organization was last modified (ISO 8601 format in UTC).",
          example = "2025-04-14T13:15:00Z")
  private Instant lastModifiedDate;

  @Schema(description = "Identifier of the user or system that created this organization.",
          example = "superuser1")
  private String createdBy;

  @Schema(description = "Identifier of the user or system that last modified this organization.",
          example = "admin@examplecorp.com")
  private String lastModifiedBy;

  /**
   * Static factory method to create an OrgResponse DTO from an Organization entity.
   * Populates the DTO fields, including derived flags like {@code hasSamlConfig}.
   * Handles null input gracefully.
   *
   * @param org The {@link Organization} entity.
   * @return A corresponding {@link OrgResponse}, or null if the input entity is null.
   */
  public static OrgResponse fromEntity(Organization org) {
    if (org == null) {
      return null;
    }
    // Uses Lombok-generated getters from the Organization entity
    return OrgResponse.builder()
            .id(org.getId())
            .orgName(org.getOrgName())
            .orgDomain(org.getOrgDomain())
            .loginType(org.getLoginType())
            .isSuperOrg(org.isSuperOrg())
            // Check if related config entities exist (might require eager fetch or check before calling)
            // Assumes getSamlConfig() and getOauth2Config() return null if not present.
            .hasSamlConfig(org.getSamlConfig() != null)
            .hasOauth2Config(org.getOauth2Config() != null)
            // Audit fields inherited from Auditable
            .createdDate(org.getCreatedDate())
            .lastModifiedDate(org.getLastModifiedDate())
            .createdBy(org.getCreatedBy())
            .lastModifiedBy(org.getLastModifiedBy())
            .build();
  }
}