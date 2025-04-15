// File: src/main/java/org/example/iam/controller/OrganizationController.java
package org.example.iam.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
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
import org.example.iam.dto.CreateOrgRequest;
import org.example.iam.dto.OrgResponse;
import org.example.iam.dto.UpdateOrgRequest;
import org.example.iam.security.SecurityUtils;
import org.example.iam.service.OrganizationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*; // Import DELETE mapping

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * REST Controller for managing Organizations (tenants) within the IAM system.
 * Provides endpoints for creating, retrieving, updating, and deleting organizations.
 * Requires appropriate authentication and authorization based on the operation and target organization.
 */
@RestController
@RequestMapping("/api/v1/organizations") // Base path for organization operations
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Organization Management", description = "Endpoints for managing organizations (tenants)")
@SecurityRequirement(name = "bearerAuth") // Indicate JWT Bearer token is generally required
public class OrganizationController {

  private final OrganizationService organizationService;

  /**
   * Creates a new organization. Requires SUPER role.
   *
   * @param createOrgRequest DTO containing details for the new organization.
   * @return ResponseEntity containing ApiResponse<OrgResponse> or ApiError.
   */
  @Operation(summary = "Create Organization",
          description = "Creates a new organization (tenant). This operation requires the SUPER role.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "201", description = ApiResponseMessages.ORG_CREATED_SUCCESS,
                  content = @Content(mediaType = "application/json",
                          schema = @Schema(implementation = ApiResponse.class))), // Ref standard response
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "409", description = ApiErrorMessages.ORG_NAME_ALREADY_EXISTS + " or " + ApiErrorMessages.ORG_DOMAIN_ALREADY_EXISTS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PostMapping
  @PreAuthorize("hasRole('SUPER')") // Enforce SUPER role requirement
  public ResponseEntity<ApiSuccessResponse<OrgResponse>> createOrganization(
          @Valid @RequestBody CreateOrgRequest createOrgRequest) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    log.info("Actor '{}' attempting to create organization with name '{}' and domain '{}'",
            actorUsername, createOrgRequest.getOrgName(), createOrgRequest.getOrgDomain());

    OrgResponse createdOrg = organizationService.createOrganization(createOrgRequest, actorUsername);

    ApiSuccessResponse<OrgResponse> response = ApiSuccessResponse.created(createdOrg, ApiResponseMessages.ORG_CREATED_SUCCESS);
    // Return 201 Created status
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  /**
   * Retrieves details for a specific organization by its ID.
   * Requires authentication. SUPER users can get any org, ADMIN/USER can only get their own.
   *
   * @param orgId UUID of the organization to retrieve.
   * @return ResponseEntity containing ApiResponse<OrgResponse> or ApiError.
   */
  @Operation(summary = "Get Organization by ID",
          description = "Retrieves details for a specific organization. Requires authentication. SUPER users can get any org, while ADMIN/USER users can only retrieve their own organization's details.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_RETRIEVED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED, // If user tries to access other org
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping("/{orgId}")
  @PreAuthorize("isAuthenticated()") // Basic check, service layer handles fine-grained access
  public ResponseEntity<ApiSuccessResponse<OrgResponse>> getOrganizationById(
          @Parameter(description = "UUID of the organization to retrieve", required = true) @PathVariable UUID orgId) {

    // Extract actor details for authorization check in service layer
    String actorUsername = SecurityUtils.getCurrentUsername().orElse("UnknownActor");
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to retrieve organization ID '{}'",
            actorUsername, actorOrgId, actorRoles, orgId);

    // Service layer performs authorization check (isSuper or isMemberOfOrg)
    OrgResponse orgResponse = organizationService.getOrganizationById(orgId, actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<OrgResponse> response = ApiSuccessResponse.ok(orgResponse, ApiResponseMessages.ORG_RETRIEVED_SUCCESS);
    return ResponseEntity.ok(response);
  }

  /**
   * Retrieves a list of all organizations. Requires SUPER role.
   *
   * @return ResponseEntity containing ApiResponse<List<OrgResponse>> or ApiError.
   */
  @Operation(summary = "Get All Organizations",
          description = "Retrieves a list of all organizations in the system. Requires SUPER role.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ALL_ORGS_RETRIEVED_SUCCESS,
                  content = @Content(mediaType = "application/json",
                          array = @ArraySchema(schema = @Schema(implementation = OrgResponse.class)))), // Note array schema
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @GetMapping
  @PreAuthorize("hasRole('SUPER')") // Enforce SUPER role
  public ResponseEntity<ApiSuccessResponse<List<OrgResponse>>> getAllOrganizations() {
    String actorUsername = SecurityUtils.getCurrentUsername().orElse("UnknownSuperUser");
    log.info("Actor '{}' retrieving all organizations", actorUsername);

    List<OrgResponse> organizations = organizationService.getAllOrganizations(actorUsername);

    ApiSuccessResponse<List<OrgResponse>> response = ApiSuccessResponse.ok(organizations, ApiResponseMessages.ALL_ORGS_RETRIEVED_SUCCESS);
    return ResponseEntity.ok(response);
  }

  /**
   * Updates an existing organization's name or login type.
   * Requires SUPER role, or ADMIN role of the specific organization. Domain cannot be changed via this endpoint.
   * Cannot be used to modify the Super Organization.
   *
   * @param orgId            UUID of the organization to update.
   * @param updateOrgRequest DTO containing the fields to update.
   * @return ResponseEntity containing ApiResponse<OrgResponse> or ApiError.
   */
  @Operation(summary = "Update Organization",
          description = "Updates an existing organization's mutable properties (e.g., name, login type). Requires SUPER role, or ADMIN role of the specific organization. Domain cannot be changed here.")
  @ApiResponses(value = {
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_UPDATED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          @ApiResponse(responseCode = "400", description = ApiErrorMessages.INVALID_INPUT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED + " or " + ApiErrorMessages.CANNOT_MODIFY_SUPER_ORG,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "409", description = ApiErrorMessages.ORG_NAME_ALREADY_EXISTS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @PutMapping("/{orgId}")
  @PreAuthorize("hasAnyRole('SUPER', 'ADMIN')") // Service checks if ADMIN is for the correct org
  public ResponseEntity<ApiSuccessResponse<OrgResponse>> updateOrganization(
          @Parameter(description = "UUID of the organization to update", required = true) @PathVariable UUID orgId,
          @Valid @RequestBody UpdateOrgRequest updateOrgRequest) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    UUID actorOrgId = SecurityUtils.getCurrentOrgId().orElse(null);
    Set<RoleType> actorRoles = SecurityUtils.getCurrentUserRoles();
    log.info("Actor '{}' (Org: {}, Roles: {}) attempting to update organization ID '{}'",
            actorUsername, actorOrgId, actorRoles, orgId);

    OrgResponse updatedOrg = organizationService.updateOrganization(orgId, updateOrgRequest,
            actorUsername, actorOrgId, actorRoles);

    ApiSuccessResponse<OrgResponse> response = ApiSuccessResponse.ok(updatedOrg, ApiResponseMessages.ORG_UPDATED_SUCCESS);
    return ResponseEntity.ok(response);
  }

  /**
   * Deletes an existing organization and its associated users, configurations, etc.
   * Requires SUPER role. Cannot delete the Super Organization. This is a destructive operation.
   *
   * @param orgId UUID of the organization to delete.
   * @return ResponseEntity containing ApiResponse<Void> or ApiError.
   */
  @Operation(summary = "Delete Organization",
          description = "Deletes an existing organization and all associated data (users, configs). Requires SUPER role. Cannot delete the Super Organization. This is irreversible.")
  @ApiResponses(value = {
          // Use 200 OK with message for consistency, though 204 No Content is also valid for DELETE
          @ApiResponse(responseCode = "200", description = ApiResponseMessages.ORG_DELETED_SUCCESS,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiResponse.class))),
          // @ApiResponse(responseCode = "204", description = "Organization deleted successfully (No Content)"), // Alternative
          @ApiResponse(responseCode = "401", description = ApiErrorMessages.INVALID_JWT,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "403", description = ApiErrorMessages.ACCESS_DENIED + " or " + ApiErrorMessages.CANNOT_DELETE_SUPER_ORG,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class))),
          @ApiResponse(responseCode = "404", description = ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID,
                  content = @Content(mediaType = "application/json", schema = @Schema(implementation = ApiError.class)))
  })
  @DeleteMapping("/{orgId}")
  @PreAuthorize("hasRole('SUPER')") // Only SUPER users can delete organizations
  public ResponseEntity<ApiSuccessResponse<Void>> deleteOrganization(
          @Parameter(description = "UUID of the organization to delete", required = true) @PathVariable UUID orgId) {

    String actorUsername = SecurityUtils.getCurrentUsername()
            .orElseThrow(() -> new IllegalStateException("Authenticated user details unexpectedly missing"));
    log.warn("Actor '{}' initiating DELETE operation for organization ID: {}", actorUsername, orgId);

    // Delegate deletion logic, including checks (isSuperOrg), to the service layer
    organizationService.deleteOrganization(orgId, actorUsername);

    // Build success response (200 OK with message)
    ApiSuccessResponse<Void> response = ApiSuccessResponse.ok(ApiResponseMessages.ORG_DELETED_SUCCESS);
    log.info("Organization ID '{}' successfully deleted by actor '{}'.", orgId, actorUsername);

    // Alternative: Return 204 No Content (no response body)
    // return ResponseEntity.noContent().build();

    return ResponseEntity.ok(response);
  }

}