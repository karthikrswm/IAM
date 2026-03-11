// File: src/main/java/org/example/iam/controller/ConfigController.java
package org.example.iam.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiError;
import org.example.iam.api.ApiSuccessResponse;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.ApiResponseMessages;
import org.example.iam.constant.RoleType;
import org.example.iam.dto.Oauth2ConfigDto;
import org.example.iam.dto.SamlConfigDto;
import org.example.iam.security.SecurityUtils;
import org.example.iam.service.ConfigService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.UUID;

/**
 * REST Controller for managing Organization-specific configurations, such as SAML 2.0
 * and OAuth 2.0 settings for Single Sign-On (SSO).
 * <p>
 * Endpoints are nested under the organization's path: {@code /api/v1/organizations/{orgId}/config}.
 * Access requires appropriate authentication and authorization (typically SUPER role or ADMIN
 * role of the specific organization).
 * </p>
 */
@RestController
@RequestMapping("/api/v1/organizations/{orgId}/config") // Nested base path
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Organization Configuration", description = "Manage SAML and OAuth2 SSO settings per organization")
@SecurityRequirement(name = "bearerAuth") // Indicate JWT Bearer token is generally required
public class ConfigController {

  private final ConfigService configService;

  // --- SAML Configuration Endpoints ---

  /**
   * Retrieves the SAML 2.0 configuration for a specific organization.
   * Requires authentication. Access is granted to SUPER users or members (ADMIN/USER)
   * of the specified organization.
   *
   * @param orgId UUID of the organization.
   * @return ResponseEntity containing ApiResponse<SamlConfigDto> or ApiError.
   */
  @Operation(summary = "Get SAML Configuration",
          description = "Retrieves the SAML 2.0 IdP configuration for the specified organization. Requires SUPER role or membership (ADMIN/USER) in the organization.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_CONFIG_RETRIEVED_SUCCESS, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID + " or SAML config not found",
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping("/saml")
  // Basic authentication check; fine-grained access control is handled in the service layer.
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<ApiSuccessResponse<SamlConfigDto>> getSamlConfiguration(
          @Parameter(description = "UUID of the organization", required = true) @PathVariable UUID orgId) {

    // Extract actor details for authorization check in service layer and logging
    String actorUsername = SecurityUtils.getCurrentUsername().orElse("UnknownActor");
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to retrieve SAML config for Org ID '{}'",
            actorUsername, actorOrgId, actorRoles, orgId);

    SamlConfigDto configDto = configService.getSamlConfig(orgId, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<SamlConfigDto> response = ApiSuccessResponse.ok(configDto, ApiResponseMessages.ORG_CONFIG_RETRIEVED_SUCCESS); // Use constant
    return ResponseEntity.ok(response);
  }

  /**
   * Creates or updates the SAML 2.0 configuration for a specific organization.
   * Requires SUPER role, or ADMIN role of the specified organization.
   * Cannot be used for the Super Organization.
   *
   * @param orgId         UUID of the organization.
   * @param samlConfigDto DTO containing the SAML configuration details.
   * @return ResponseEntity containing ApiResponse<SamlConfigDto> or ApiError.
   */
  @Operation(summary = "Update SAML Configuration",
          description = "Creates or updates the SAML 2.0 IdP configuration for the specified organization. Requires SUPER role or ADMIN role of the organization.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_SAML_CONFIG_UPDATED, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED + " or " + ApiErrorMessages.OPERATION_NOT_ALLOWED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PutMapping("/saml")
  // Requires SUPER role globally, or ADMIN role (service layer verifies it's for the correct org)
  @PreAuthorize("hasAnyRole('SUPER', 'ADMIN')")
  public ResponseEntity<ApiSuccessResponse<SamlConfigDto>> updateSamlConfiguration(
          @Parameter(description = "UUID of the organization", required = true) @PathVariable UUID orgId,
          @Valid @RequestBody SamlConfigDto samlConfigDto) {

    // Extract actor details for authorization and auditing
    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing")); // Should not happen if @PreAuthorize passes
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to update SAML config for Org ID '{}'",
            actorUsername, actorOrgId, actorRoles, orgId);

    SamlConfigDto updatedConfig = configService.saveOrUpdateSamlConfig(orgId, samlConfigDto,
            actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<SamlConfigDto> response = ApiSuccessResponse.ok(updatedConfig, ApiResponseMessages.ORG_SAML_CONFIG_UPDATED); // Use constant
    return ResponseEntity.ok(response);
  }

  /**
   * Generates and returns the SAML 2.0 Service Provider metadata XML for the organization.
   * Requires SUPER role or ADMIN role of the specified organization.
   *
   * @param orgId UUID of the organization.
   * @return ResponseEntity containing the metadata XML string or ApiError.
   */
  @Operation(summary = "Get SAML SP Metadata", // <<< ADDED Endpoint
          description = "Generates and returns the SAML 2.0 Service Provider metadata XML document...")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = "SAML SP Metadata XML generated successfully",
                  content = @Content(mediaType = "application/samlmetadata+xml", schema = @Schema(type = "string", format = "xml"))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.AUTHENTICATION_FAILED, content = @Content(schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED, content = @Content(schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID + " or SAML config not found/disabled", content = @Content(schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "500", description = ApiErrorMessages.CONFIGURATION_ERROR + " (Metadata generation failed)", content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping(value = "/saml/metadata", produces = {"application/samlmetadata+xml", MediaType.APPLICATION_JSON_VALUE})
  @PreAuthorize("hasAnyRole('SUPER', 'ADMIN')")
  public ResponseEntity<String> getSpMetadata(
          @Parameter(description = "UUID of the organization", required = true) @PathVariable UUID orgId) {

    String actorUsername = SecurityUtils.getCurrentUsername().orElse("UnknownActor");
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' requesting SAML SP metadata for Org ID '{}'", actorUsername, orgId);

    String metadataXml = configService.generateSpMetadataXml(orgId, actorUsername, actorOrgId, actorRoles);

    return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType("application/samlmetadata+xml"))
            .header("Content-Disposition", "attachment; filename=\"sp-metadata-" + orgId + ".xml\"")
            .body(metadataXml);
  }



  // --- OAuth2 Configuration Endpoints ---

  /**
   * Retrieves the OAuth 2.0 client configuration for a specific organization.
   * Requires authentication. Access is granted to SUPER users or members (ADMIN/USER)
   * of the specified organization.
   *
   * @param orgId UUID of the organization.
   * @return ResponseEntity containing ApiResponse<Oauth2ConfigDto> or ApiError.
   */
  @Operation(summary = "Get OAuth2 Configuration",
          description = "Retrieves the OAuth 2.0 client configuration for the specified organization. Requires SUPER role or membership (ADMIN/USER) in the organization.")
  @ApiResponses(value = { // Similar responses as GET /saml
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_CONFIG_RETRIEVED_SUCCESS, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID + " or OAuth2 config not found",
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping("/oauth2")
  @PreAuthorize("isAuthenticated()") // Service layer handles detailed auth check
  public ResponseEntity<ApiSuccessResponse<Oauth2ConfigDto>> getOauth2Configuration(
          @Parameter(description = "UUID of the organization", required = true) @PathVariable UUID orgId) {

    String actorUsername = SecurityUtils.getCurrentUsername().orElse("UnknownActor");
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to retrieve OAuth2 config for Org ID '{}'",
            actorUsername, actorOrgId, actorRoles, orgId);

    Oauth2ConfigDto configDto = configService.getOauth2Config(orgId, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<Oauth2ConfigDto> response = ApiSuccessResponse.ok(configDto, ApiResponseMessages.ORG_CONFIG_RETRIEVED_SUCCESS); // Use constant
    return ResponseEntity.ok(response);
  }

  /**
   * Creates or updates the OAuth 2.0 client configuration for a specific organization.
   * Requires SUPER role, or ADMIN role of the specified organization.
   * Cannot be used for the Super Organization. Sensitive fields like client secret are handled appropriately.
   *
   * @param orgId           UUID of the organization.
   * @param oauth2ConfigDto DTO containing the OAuth2 configuration details.
   * @return ResponseEntity containing ApiResponse<Oauth2ConfigDto> or ApiError.
   */
  @Operation(summary = "Update OAuth2 Configuration",
          description = "Creates or updates the OAuth 2.0 client configuration for the specified organization. Requires SUPER role or ADMIN role of the organization.")
  @ApiResponses(value = { // Similar responses as PUT /saml
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_OAUTH2_CONFIG_UPDATED, // Use constant
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiSuccessResponse.class))), // Use ApiSuccessResponse
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED + " or " + ApiErrorMessages.OPERATION_NOT_ALLOWED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PutMapping("/oauth2")
  @PreAuthorize("hasAnyRole('SUPER', 'ADMIN')") // Service verifies ADMIN is for the correct org
  public ResponseEntity<ApiSuccessResponse<Oauth2ConfigDto>> updateOauth2Configuration(
          @Parameter(description = "UUID of the organization", required = true) @PathVariable UUID orgId,
          @Valid @RequestBody Oauth2ConfigDto oauth2ConfigDto) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to update OAuth2 config for Org ID '{}'",
            actorUsername, actorOrgId, actorRoles, orgId);

    Oauth2ConfigDto updatedConfig = configService.saveOrUpdateOauth2Config(orgId, oauth2ConfigDto,
            actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<Oauth2ConfigDto> response = ApiSuccessResponse.ok(updatedConfig, ApiResponseMessages.ORG_OAUTH2_CONFIG_UPDATED); // Use constant
    return ResponseEntity.ok(response);
  }
}