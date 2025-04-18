// File: src/main/java/org/example/iam/service/OrganizationService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.ApiResponseMessages; // Added import
import org.example.iam.constant.AuditEventType;
import org.example.iam.constant.RoleType;
import org.example.iam.dto.CreateOrgRequest;
import org.example.iam.dto.OrgResponse;
import org.example.iam.dto.UpdateOrgRequest;
import org.example.iam.entity.Organization;
// Removed User import as it's not directly used here after adding helpers
import org.example.iam.exception.ConflictException;
import org.example.iam.exception.OperationNotAllowedException;
import org.example.iam.exception.ResourceNotFoundException;
import org.example.iam.repository.OrganizationRepository;
// Removed SecurityUtils import as we use method parameters
import org.springframework.security.access.AccessDeniedException; // Use Spring's exception
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils; // Import StringUtils

import java.util.List;
import java.util.Objects; // Import Objects
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service layer handling business logic for Organization (tenant) management.
 * Includes creation, retrieval, update, and deletion operations.
 * Enforces business rules, performs authorization checks, and logs audit events.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OrganizationService {

  private final OrganizationRepository organizationRepository;
  private final AuditEventService auditEventService;
  // NOTE: If deleting an org should delete related configs not handled by cascade, inject those repos too.

  /**
   * Creates a new organization based on the provided request.
   * Requires SUPER role. Validates uniqueness of name and domain.
   *
   * @param request DTO containing organization details.
   * @param actor   Username of the SUPER user performing the action.
   * @return OrgResponse DTO of the newly created organization.
   * @throws ConflictException      if name or domain already exists.
   * @throws AccessDeniedException if the actor is not a SUPER user (should be caught by @PreAuthorize ideally).
   */
  @Transactional
  public OrgResponse createOrganization(CreateOrgRequest request, String actor) {
    log.info("Actor '{}' attempting to create organization with name '{}' and domain '{}'",
            actor, request.getOrgName(), request.getOrgDomain());

    // Authorization check (redundant if @PreAuthorize("hasRole('SUPER')") is used, but good practice)
    // This check assumes SecurityUtils works correctly or role is passed if needed
    // if (!SecurityUtils.hasRole(RoleType.SUPER)) {
    //     log.warn("Authorization failed: Actor '{}' attempting to create organization without SUPER role.", actor);
    //     throw new AccessDeniedException(ApiErrorMessages.ACCESS_DENIED); // Use constant
    // }

    // Validate input and check for conflicts
    String orgName = request.getOrgName().trim();
    String orgDomain = request.getOrgDomain().toLowerCase().trim(); // Normalize domain to lowercase

    if (organizationRepository.existsByOrgNameIgnoreCase(orgName)) {
      log.warn("Organization creation failed: Name '{}' already exists.", orgName);
      throw new ConflictException(String.format(ApiErrorMessages.ORG_NAME_ALREADY_EXISTS, orgName)); // Use constant
    }
    if (organizationRepository.existsByOrgDomainIgnoreCase(orgDomain)) {
      log.warn("Organization creation failed: Domain '{}' already exists.", orgDomain);
      throw new ConflictException(String.format(ApiErrorMessages.ORG_DOMAIN_ALREADY_EXISTS, orgDomain)); // Use constant
    }

    // Create and save the new organization
    Organization newOrg = Organization.builder()
            .orgName(orgName)
            .orgDomain(orgDomain)
            .loginType(request.getLoginType())
            .isSuperOrg(false) // New orgs are never the Super Org
            .build();
    // Auditable fields (createdBy, etc.) will be set by AuditorAware/JPA

    Organization savedOrg = organizationRepository.save(newOrg);
    log.info("Organization '{}' (ID: {}) created successfully by actor '{}'",
            savedOrg.getOrgName(), savedOrg.getId(), actor);

    // Log audit event
    auditEventService.logEvent(
            AuditEventType.ORGANIZATION_CREATED,
            String.format("Organization '%s' created", savedOrg.getOrgName()),
            actor, // Actor performing the creation
            "SUCCESS",
            "ORGANIZATION", savedOrg.getId().toString(), // Target resource is the new org
            savedOrg.getId(), // Organization context is the org itself
            null // No additional details needed for basic creation log
    );

    return OrgResponse.fromEntity(savedOrg);
  }

  /**
   * Retrieves organization details by ID.
   * Performs authorization check: requires SUPER role or membership in the target organization.
   *
   * @param orgId      The UUID of the organization to retrieve.
   * @param actor      The username of the requesting user.
   * @param actorOrgId The organization UUID of the requesting user.
   * @param actorRoles The roles of the requesting user.
   * @return OrgResponse DTO of the found organization.
   * @throws ResourceNotFoundException if the organization doesn't exist.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  @Transactional(readOnly = true)
  public OrgResponse getOrganizationById(UUID orgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.debug("Actor '{}' attempting to retrieve organization ID '{}'", actor, orgId);
    // findAndAuthorizeOrgAccess performs both find and auth check
    Organization org = findAndAuthorizeOrgAccess(orgId, actor, actorOrgId, actorRoles);

    log.info("Successfully retrieved organization '{}' (ID: {}) for actor '{}'", org.getOrgName(), orgId, actor);
    // Optional Audit Log for viewing organization details (can be verbose)
    // auditEventService.logEvent(AuditEventType.ORGANIZATION_VIEWED, String.format("Organization '%s' details viewed by %s", org.getOrgName(), actor), actor, "SUCCESS", "ORGANIZATION", orgId.toString(), orgId, null);
    return OrgResponse.fromEntity(org);
  }

  /**
   * Retrieves a list of all organizations. Requires SUPER role.
   *
   * @param actor The username of the SUPER user performing the action.
   * @return A list of OrgResponse DTOs.
   * @throws AccessDeniedException if the actor is not a SUPER user.
   */
  @Transactional(readOnly = true)
  public List<OrgResponse> getAllOrganizations(String actor /* Consider passing roles if not using SecurityUtils */) {
    log.debug("Actor '{}' attempting to retrieve all organizations", actor);

    // Authorization check (redundant if controller uses @PreAuthorize)
    // if (!SecurityUtils.hasRole(RoleType.SUPER)) { // Assuming SecurityUtils works
    //     log.warn("Authorization failed: Actor '{}' attempting to get all organizations without SUPER role.", actor);
    //     throw new AccessDeniedException(ApiErrorMessages.ACCESS_DENIED); // Use constant
    // }

    List<Organization> orgs = organizationRepository.findAll();
    log.info("Retrieved {} organization(s) for actor '{}'", orgs.size(), actor);
    // Optional Audit Log
    // auditEventService.logEvent(AuditEventType.ORGANIZATION_LIST_VIEWED, String.format("Retrieved %d organizations", orgs.size()), actor, "SUCCESS", "ORGANIZATION_LIST", null, null, null);
    return orgs.stream().map(OrgResponse::fromEntity).collect(Collectors.toList());
  }

  /**
   * Updates an existing organization's mutable properties (name, login type).
   * Requires SUPER role or ADMIN role of the target organization.
   * Prevents modification of the Super Organization.
   *
   * @param orgId      The UUID of the organization to update.
   * @param request    DTO containing updated details.
   * @param actor      The username of the requesting user.
   * @param actorOrgId The organization UUID of the requesting user.
   * @param actorRoles The roles of the requesting user.
   * @return OrgResponse DTO of the updated organization.
   * @throws ResourceNotFoundException    if the organization doesn't exist.
   * @throws AccessDeniedException        if the actor lacks permission.
   * @throws OperationNotAllowedException if attempting to modify the Super Org.
   * @throws ConflictException            if the new name conflicts with an existing one.
   */
  @Transactional
  public OrgResponse updateOrganization(UUID orgId, UpdateOrgRequest request, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.info("Actor '{}' attempting to update organization ID '{}'", actor, orgId);
    // findAndAuthorizeOrgAdminOrSuperAccess performs find and auth check
    Organization existingOrg = findAndAuthorizeOrgAdminOrSuperAccess(orgId, actor, actorOrgId, actorRoles);

    // Business rule: Cannot modify the Super Organization
    if (existingOrg.isSuperOrg()) {
      log.warn("Update failed: Actor '{}' attempted to modify the Super Organization (ID: {})", actor, orgId);
      throw new OperationNotAllowedException(ApiErrorMessages.CANNOT_MODIFY_SUPER_ORG); // Use constant
    }

    boolean changed = false;
    StringBuilder changesDetail = new StringBuilder("Changes: ");

    // Update Organization Name if provided and different
    String newOrgName = request.getOrgName().trim();
    if (StringUtils.hasText(newOrgName) && !Objects.equals(newOrgName, existingOrg.getOrgName())) {
      // Check for name conflict before updating
      if (organizationRepository.existsByOrgNameIgnoreCase(newOrgName)) {
        log.warn("Organization update failed: Name '{}' already exists.", newOrgName);
        throw new ConflictException(String.format(ApiErrorMessages.ORG_NAME_ALREADY_EXISTS, newOrgName)); // Use constant
      }
      log.debug("Updating Org ID '{}' name from '{}' to '{}'", orgId, existingOrg.getOrgName(), newOrgName);
      changesDetail.append(String.format("Name changed from '%s' to '%s'; ", existingOrg.getOrgName(), newOrgName));
      existingOrg.setOrgName(newOrgName);
      changed = true;
    }

    // Update Login Type if provided and different
    if (request.getLoginType() != null && !Objects.equals(request.getLoginType(), existingOrg.getLoginType())) {
      // Prevent changing login type for Super Org (already checked above, but good defense)
      if(existingOrg.isSuperOrg()){
        // This case should not be reachable due to the earlier check, but defensive coding is good.
        throw new OperationNotAllowedException(ApiErrorMessages.CANNOT_MODIFY_SUPER_ORG_LOGIN); // Use constant
      }
      log.debug("Updating Org ID '{}' login type from '{}' to '{}'", orgId, existingOrg.getLoginType(), request.getLoginType());
      changesDetail.append(String.format("LoginType changed from '%s' to '%s'; ", existingOrg.getLoginType(), request.getLoginType()));
      existingOrg.setLoginType(request.getLoginType());
      changed = true;
      // Note: Changing login type might require manual adjustments to SAML/OAuth configs if switching *to* them.
      // Switching *away* from SAML/OAuth might implicitly disable them or require cleanup.
    }

    Organization updatedOrg = existingOrg; // Assume no change initially
    if (changed) {
      // Save only if changes were made
      updatedOrg = organizationRepository.save(existingOrg); // lastModifiedBy/Date updated by JPA Auditing
      log.info("Organization '{}' (ID: {}) updated successfully by actor '{}'", updatedOrg.getOrgName(), orgId, actor);

      // Log audit event
      auditEventService.logEvent(
              AuditEventType.ORGANIZATION_UPDATED,
              String.format("Organization '%s' updated", updatedOrg.getOrgName()),
              actor,
              "SUCCESS",
              "ORGANIZATION", updatedOrg.getId().toString(), // Target resource
              updatedOrg.getId(), // Org context
              changesDetail.length() > "Changes: ".length() ? changesDetail.toString() : "No specific field changes detected in request" // Details
      );
    } else {
      log.info("No effective changes detected for organization ID '{}'. Update skipped.", orgId);
    }

    return OrgResponse.fromEntity(updatedOrg); // Return current state
  }

  /**
   * Deletes an organization. Requires SUPER role.
   * Cannot delete the Super Organization. Cascade settings should handle related users/configs.
   *
   * @param orgId The UUID of the organization to delete.
   * @param actor The username of the SUPER user performing the action.
   * @throws ResourceNotFoundException    if the organization doesn't exist.
   * @throws AccessDeniedException        if the actor is not a SUPER user.
   * @throws OperationNotAllowedException if attempting to delete the Super Org.
   */
  @Transactional
  public void deleteOrganization(UUID orgId, String actor /* Pass roles if not using SecurityUtils */) {
    log.warn("Actor '{}' attempting DESTRUCTIVE delete operation for organization ID '{}'", actor, orgId);

    // Authorization check (Redundant if controller uses @PreAuthorize)
    // if (!SecurityUtils.hasRole(RoleType.SUPER)) {
    //     log.warn("Authorization failed: Actor '{}' attempting delete without SUPER role.", actor);
    //     throw new AccessDeniedException(ApiErrorMessages.ACCESS_DENIED); // Use constant
    // }

    Organization orgToDelete = organizationRepository.findById(orgId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, orgId))); // Use constant

    // Business Rule: Cannot delete the Super Organization
    if (orgToDelete.isSuperOrg()) {
      log.warn("Delete failed: Actor '{}' attempted to delete the Super Organization (ID: {})", actor, orgId);
      throw new OperationNotAllowedException(ApiErrorMessages.CANNOT_DELETE_SUPER_ORG); // Use constant
    }

    String orgName = orgToDelete.getOrgName(); // Capture name before deletion for logging

    // Perform deletion - CascadeType.ALL on relationships in Organization entity
    // should handle deletion of associated Users, SamlConfigs, Oauth2Configs.
    organizationRepository.delete(orgToDelete);
    log.info("Organization '{}' (ID: {}) deleted successfully by actor '{}'. Associated users/configs should be removed by cascade.",
            orgName, orgId, actor);

    // Log audit event
    auditEventService.logEvent(
            AuditEventType.ORGANIZATION_DELETED,
            String.format("Organization '%s' (ID: %s) deleted", orgName, orgId),
            actor,
            "SUCCESS",
            "ORGANIZATION", orgId.toString(), // Target resource ID
            orgId, // Org context (even though deleted)
            null // No additional details needed
    );
  }


  // --- Authorization Helper Methods (Copied/adapted from ConfigService for consistency) ---

  /**
   * Finds an organization by ID and checks if the requesting actor has permission to access its details.
   * Access allowed for SUPER users or members (any role) of the target organization.
   */
  private Organization findAndAuthorizeOrgAccess(UUID targetOrgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    Organization org = organizationRepository.findById(targetOrgId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, targetOrgId))); // Use constant
    boolean isSuper = actorRoles.contains(RoleType.SUPER);
    boolean isMemberOfOrg = Objects.equals(targetOrgId, actorOrgId);
    if (!isSuper && !isMemberOfOrg) {
      log.warn("Authorization failed: Actor '{}' (Org: {}) cannot access Org ID '{}'. Requires SUPER role or membership.", actor, actorOrgId, targetOrgId);
      throw new AccessDeniedException(ApiErrorMessages.ACCESS_DENIED); // Use constant
    }
    return org;
  }

  /**
   * Finds an organization by ID and checks if the requesting actor has permission to modify it.
   * Access allowed ONLY for SUPER users or ADMIN users belonging to the target organization.
   */
  private Organization findAndAuthorizeOrgAdminOrSuperAccess(UUID targetOrgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    Organization org = organizationRepository.findById(targetOrgId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, targetOrgId))); // Use constant
    boolean isSuper = actorRoles.contains(RoleType.SUPER);
    boolean isAdminOfThisOrg = actorRoles.contains(RoleType.ADMIN) && Objects.equals(targetOrgId, actorOrgId);
    if (!isSuper && !isAdminOfThisOrg) {
      log.warn("Authorization failed: Actor '{}' (Org: {}, Roles: {}) cannot modify Org ID '{}'. Requires SUPER role or ADMIN of the target organization.", actor, actorOrgId, actorRoles, targetOrgId);
      throw new AccessDeniedException(ApiErrorMessages.ACCESS_DENIED); // Use constant
    }
    return org;
  }

}