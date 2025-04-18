// File: src/main/java/org/example/iam/service/ConfigService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.ApiResponseMessages;
import org.example.iam.constant.AuditEventType;
import org.example.iam.constant.RoleType;
import org.example.iam.dto.Oauth2ConfigDto;
import org.example.iam.dto.SamlConfigDto;
import org.example.iam.entity.Oauth2Config;
import org.example.iam.entity.Organization;
import org.example.iam.entity.SamlConfig;
import org.example.iam.exception.BadRequestException;
import org.example.iam.exception.ConfigurationException; // For config issues
import org.example.iam.exception.OperationNotAllowedException;
import org.example.iam.exception.ResourceNotFoundException;
import org.example.iam.repository.Oauth2ConfigRepository;
import org.example.iam.repository.OrganizationRepository;
import org.example.iam.repository.SamlConfigRepository;
// Removed unused SecurityUtils import, using params directly
import org.springframework.security.access.AccessDeniedException; // Use Spring's exception
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Objects; // Import Objects
import java.util.Set;
import java.util.UUID;

/**
 * Service layer responsible for managing Organization-specific configurations,
 * primarily SAML 2.0 and OAuth 2.0 settings for Single Sign-On (SSO).
 * <p>
 * Handles fetching, creating, and updating configurations, including authorization checks
 * based on user roles and organization membership. Interacts with configuration repositories,
 * auditing services, and the encryption service for sensitive data.
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ConfigService {

  // --- Dependencies ---
  private final OrganizationRepository organizationRepository;
  private final SamlConfigRepository samlConfigRepository;
  private final Oauth2ConfigRepository oauth2ConfigRepository;
  private final AuditEventService auditEventService;
  private final EncryptionService encryptionService;
  // private final CredentialService credentialService; // Not needed for save/update usually

  // --- SAML Configuration Methods ---

  /**
   * Retrieves the SAML configuration DTO for a given organization ID.
   * Performs authorization check: requires SUPER role or membership in the target organization.
   *
   * @param orgId      The UUID of the organization.
   * @param actor      The username of the requesting user (for logging/auditing).
   * @param actorOrgId The organization UUID of the requesting user.
   * @param actorRoles The roles of the requesting user.
   * @return The {@link SamlConfigDto}.
   * @throws ResourceNotFoundException if the organization or its SAML config doesn't exist.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  @Transactional(readOnly = true)
  public SamlConfigDto getSamlConfig(UUID orgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.debug("Actor '{}' retrieving SAML config for Org ID '{}'", actor, orgId);
    Organization org = findAndAuthorizeOrgAccess(orgId, actor, actorOrgId, actorRoles); // Auth check

    SamlConfig config = samlConfigRepository.findByOrganization(org)
            .orElseThrow(() -> new ResourceNotFoundException("SAML configuration not found for organization: " + orgId));

    // Log successful access audit event
    auditEventService.logEvent(AuditEventType.ORG_CONFIG_UPDATED,
            String.format("SAML config accessed for organization '%s' by %s", org.getOrgName(), actor),
            actor,
            "SUCCESS",
            "SAML_CONFIG", config.getId().toString(), orgId,
            null);

    log.info("Successfully retrieved SAML config ID {} for Org '{}' by actor '{}'", config.getId(), org.getOrgName(), actor);
    return SamlConfigDto.fromEntity(config);
  }

  /**
   * Creates or updates the SAML configuration for a given organization.
   * Encrypts keystore passwords before saving.
   *
   * @param orgId         The UUID of the organization.
   * @param dto           The {@link SamlConfigDto} containing new/updated configuration data (passwords in plaintext).
   * @param actor         The username of the requesting user.
   * @param actorOrgId    The organization UUID of the requesting user.
   * @param actorRoles    The roles of the requesting user.
   * @return The updated/created {@link SamlConfigDto} (excluding sensitive fields).
   * @throws ResourceNotFoundException    if the organization doesn't exist.
   * @throws AccessDeniedException        if the actor lacks permission.
   * @throws OperationNotAllowedException if attempting to configure the Super Org.
   * @throws BadRequestException          if required fields in the DTO are missing.
   * @throws RuntimeException if encryption fails.
   */
  @Transactional
  public SamlConfigDto saveOrUpdateSamlConfig(UUID orgId, SamlConfigDto dto, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.info("Actor '{}' saving/updating SAML config for Org ID '{}'", actor, orgId);
    Organization org = findAndAuthorizeOrgAdminOrSuperAccess(orgId, actor, actorOrgId, actorRoles); // Auth check

    if (org.isSuperOrg()) {
      throw new OperationNotAllowedException("SAML configuration is not applicable to the Super Organization.");
    }

    SamlConfig config = samlConfigRepository.findByOrganization(org)
            .orElseGet(() -> {
              log.info("No existing SAML config found for Org ID '{}', creating new.", orgId);
              return SamlConfig.builder().organization(org).build();
            });

    boolean isNewConfig = (config.getId() == null);
    AuditEventType eventType = AuditEventType.ORG_CONFIG_UPDATED;
    String actionVerb = isNewConfig ? "created" : "updated";

    // --- Map DTO fields to Entity ---
    if (!StringUtils.hasText(dto.getServiceProviderEntityId())) {
      throw new BadRequestException("Service Provider Entity ID is required for SAML configuration.");
    }
    if (!StringUtils.hasText(dto.getAssertionConsumerServiceUrl())) {
      throw new BadRequestException("Assertion Consumer Service (ACS) URL is required for SAML configuration.");
    }

    config.setIdentityProviderMetadataUrl(dto.getIdentityProviderMetadataUrl());
    config.setServiceProviderEntityId(dto.getServiceProviderEntityId());
    config.setAssertionConsumerServiceUrl(dto.getAssertionConsumerServiceUrl());
    config.setSingleLogoutServiceUrl(dto.getSingleLogoutServiceUrl());
    config.setNameIdFormat(StringUtils.hasText(dto.getNameIdFormat())
            ? dto.getNameIdFormat()
            : "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    config.setSignRequests(Boolean.TRUE.equals(dto.getSignRequests()));
    config.setWantAssertionsSigned(Boolean.TRUE.equals(dto.getWantAssertionsSigned()));
    config.setAttributeMappingUsername(dto.getAttributeMappingUsername());
    config.setAttributeMappingEmail(dto.getAttributeMappingEmail());
    config.setAttributeMappingRoles(dto.getAttributeMappingRoles());
    config.setEnabled(Boolean.TRUE.equals(dto.getEnabled()));

    // --- Handle Keystore References and Encrypt Passwords ---
    try {
      // Use correct getters from DTO and setters for Entity
      if (StringUtils.hasText(dto.getSpSigningKeystorePathInput())) { // <<< CORRECTED Getter
        config.setSpSigningKeystorePath(dto.getSpSigningKeystorePathInput()); // <<< CORRECTED Setter
      }
      if (StringUtils.hasText(dto.getSpSigningKeyAliasInput())) { // <<< CORRECTED Getter
        config.setSpSigningKeyAlias(dto.getSpSigningKeyAliasInput()); // <<< CORRECTED Setter
      }
      if (StringUtils.hasText(dto.getSpSigningKeystorePasswordInput())) { // <<< CORRECTED Getter
        config.setSpSigningKeystorePasswordEncrypted(encryptionService.encrypt(dto.getSpSigningKeystorePasswordInput())); // <<< CORRECTED Setter
        log.debug("Encrypted SP Signing Keystore password for config update.");
      } else if (isNewConfig && StringUtils.hasText(config.getSpSigningKeystorePath())) {
        throw new BadRequestException("SP Signing Keystore password is required when setting the keystore path.");
      }

      if (StringUtils.hasText(dto.getSpEncryptionKeystorePathInput())) { // <<< CORRECTED Getter
        config.setSpEncryptionKeystorePath(dto.getSpEncryptionKeystorePathInput()); // <<< CORRECTED Setter
      }
      if (StringUtils.hasText(dto.getSpEncryptionKeyAliasInput())) { // <<< CORRECTED Getter
        config.setSpEncryptionKeyAlias(dto.getSpEncryptionKeyAliasInput()); // <<< CORRECTED Setter
      }
      if (StringUtils.hasText(dto.getSpEncryptionKeystorePasswordInput())) { // <<< CORRECTED Getter
        config.setSpEncryptionKeystorePasswordEncrypted(encryptionService.encrypt(dto.getSpEncryptionKeystorePasswordInput())); // <<< CORRECTED Setter
        log.debug("Encrypted SP Encryption Keystore password for config update.");
      } else if (isNewConfig && StringUtils.hasText(config.getSpEncryptionKeystorePath())) {
        throw new BadRequestException("SP Encryption Keystore password is required when setting the keystore path.");
      }

      if (StringUtils.hasText(dto.getIdpVerificationCertificatePemInput())) { // <<< CORRECTED Getter
        config.setIdpVerificationCertificatePem(dto.getIdpVerificationCertificatePemInput()); // <<< CORRECTED Setter
      }
    } catch (Exception e) {
      log.error("Failed to encrypt keystore password during SAML config update for Org ID {}: {}", orgId, e.getMessage(), e);
      throw new RuntimeException("Failed to process keystore password.", e);
    }

    // Save the entity
    SamlConfig savedConfig = samlConfigRepository.save(config);
    log.info("SAML config ID '{}' {} for Org '{}' by actor '{}'", savedConfig.getId(), actionVerb, org.getOrgName(), actor);

    // Log audit event
    auditEventService.logEvent(eventType,
            String.format("SAML config for organization '%s' %s by %s", org.getOrgName(), actionVerb, actor),
            actor, "SUCCESS",
            "SAML_CONFIG", savedConfig.getId().toString(), orgId,
            "Enabled: " + savedConfig.isEnabled());

    return SamlConfigDto.fromEntity(savedConfig);
  }

  // --- OAuth2 Configuration Methods ---

  /**
   * Retrieves the OAuth2 configuration DTO for a given organization ID.
   * Performs authorization check: requires SUPER role or membership in the target organization.
   *
   * @param orgId      The UUID of the organization.
   * @param actor      The username of the requesting user.
   * @param actorOrgId The organization UUID of the requesting user.
   * @param actorRoles The roles of the requesting user.
   * @return The {@link Oauth2ConfigDto}.
   * @throws ResourceNotFoundException if the organization or its OAuth2 config doesn't exist.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  @Transactional(readOnly = true)
  public Oauth2ConfigDto getOauth2Config(UUID orgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.debug("Actor '{}' retrieving OAuth2 config for Org ID '{}'", actor, orgId);
    Organization org = findAndAuthorizeOrgAccess(orgId, actor, actorOrgId, actorRoles); // Auth check

    Oauth2Config config = oauth2ConfigRepository.findByOrganization(org)
            .orElseThrow(() -> new ResourceNotFoundException("OAuth2 configuration not found for organization: " + orgId));

    auditEventService.logEvent(AuditEventType.ORG_CONFIG_UPDATED,
            String.format("OAuth2 config (Provider: %s) accessed for organization '%s' by %s", config.getProvider(), org.getOrgName(), actor),
            actor, "SUCCESS",
            "OAUTH2_CONFIG", config.getId().toString(), orgId,
            null);

    log.info("Successfully retrieved OAuth2 config ID {} (Provider: {}) for Org '{}' by actor '{}'", config.getId(), config.getProvider(), org.getOrgName(), actor);
    return Oauth2ConfigDto.fromEntity(config);
  }

  /**
   * Creates or updates the OAuth2 configuration for a given organization.
   * Encrypts the client secret before saving.
   *
   * @param orgId      The UUID of the organization.
   * @param dto        The {@link Oauth2ConfigDto} containing new/updated configuration data (secret in plaintext).
   * @param actor      The username of the requesting user.
   * @param actorOrgId The organization UUID of the requesting user.
   * @param actorRoles The roles of the requesting user.
   * @return The updated/created {@link Oauth2ConfigDto} (excluding sensitive fields).
   * @throws ResourceNotFoundException    if the organization doesn't exist.
   * @throws AccessDeniedException        if the actor lacks permission.
   * @throws OperationNotAllowedException if attempting to configure the Super Org.
   * @throws BadRequestException          if required fields (provider, clientId, clientSecret on create) are missing.
   * @throws RuntimeException if encryption fails.
   */
  @Transactional
  public Oauth2ConfigDto saveOrUpdateOauth2Config(UUID orgId, Oauth2ConfigDto dto, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    log.info("Actor '{}' saving/updating OAuth2 config for Org ID '{}'", actor, orgId);
    Organization org = findAndAuthorizeOrgAdminOrSuperAccess(orgId, actor, actorOrgId, actorRoles); // Auth check

    if (org.isSuperOrg()) {
      throw new OperationNotAllowedException("OAuth2 configuration is not applicable to the Super Organization.");
    }

    Oauth2Config config = oauth2ConfigRepository.findByOrganization(org)
            .orElseGet(() -> {
              log.info("No existing OAuth2 config found for Org ID '{}', creating new.", orgId);
              return Oauth2Config.builder().organization(org).build();
            });

    boolean isNewConfig = (config.getId() == null);
    AuditEventType eventType = AuditEventType.ORG_CONFIG_UPDATED;
    String actionVerb = isNewConfig ? "created" : "updated";

    // --- Map DTO fields to Entity ---
    if (!StringUtils.hasText(dto.getProvider())) {
      throw new BadRequestException("Provider identifier is required for OAuth2 configuration.");
    }
    if (!StringUtils.hasText(dto.getClientId())) {
      throw new BadRequestException("Client ID is required for OAuth2 configuration.");
    }

    config.setProvider(dto.getProvider());
    config.setClientId(dto.getClientId());

    // Handle Client Secret Encryption
    if (StringUtils.hasText(dto.getClientSecretInput())) {
      try {
        String encryptedSecret = encryptionService.encrypt(dto.getClientSecretInput());
        // Use the correct setter for the renamed field in Oauth2Config
        config.setClientSecretEncrypted(encryptedSecret); // <<< Use correct setter
        log.debug("Encrypted OAuth2 client secret for config update.");
      } catch (Exception e) {
        log.error("Failed to encrypt OAuth2 client secret during config update for Org ID {}: {}", orgId, e.getMessage(), e);
        throw new RuntimeException("Failed to process client secret.", e);
      }
    } else if (isNewConfig) {
      throw new BadRequestException("Client Secret is required when creating a new OAuth2 configuration.");
    }

    // Map remaining fields
    config.setAuthorizationUri(dto.getAuthorizationUri());
    config.setTokenUri(dto.getTokenUri());
    config.setUserInfoUri(dto.getUserInfoUri());
    config.setJwkSetUri(dto.getJwkSetUri());
    config.setRedirectUriTemplate(dto.getRedirectUriTemplate());
    config.setScopes(StringUtils.hasText(dto.getScopes()) ? dto.getScopes() : "openid,profile,email");
    config.setUserNameAttributeName(StringUtils.hasText(dto.getUserNameAttributeName())
            ? dto.getUserNameAttributeName() : "sub");
    config.setUserEmailAttributeName(StringUtils.hasText(dto.getUserEmailAttributeName())
            ? dto.getUserEmailAttributeName() : "email");
    config.setEnabled(Boolean.TRUE.equals(dto.getEnabled()));

    // Save the entity
    Oauth2Config savedConfig = oauth2ConfigRepository.save(config);
    log.info("OAuth2 config ID '{}' (Provider: {}) {} for Org '{}' by actor '{}'",
            savedConfig.getId(), savedConfig.getProvider(), actionVerb, org.getOrgName(), actor);

    // Log audit event
    auditEventService.logEvent(eventType,
            String.format("OAuth2 config (Provider: %s) for org '%s' %s by %s",
                    savedConfig.getProvider(), org.getOrgName(), actionVerb, actor),
            actor, "SUCCESS",
            "OAUTH2_CONFIG", savedConfig.getId().toString(), orgId,
            "Enabled: " + savedConfig.isEnabled());

    return Oauth2ConfigDto.fromEntity(savedConfig);
  }


  // --- Helper Methods for Authorization Checks --- (Original Comments Preserved)
  /**
   * Finds an organization by ID and checks if the requesting actor has permission to access its details.
   * Access allowed for SUPER users or members (any role) of the target organization.
   *
   * @param targetOrgId The UUID of the organization being accessed.
   * @param actor       The username of the requesting actor.
   * @param actorOrgId  The organization UUID of the requesting actor.
   * @param actorRoles  The roles of the requesting actor.
   * @return The found {@link Organization} entity.
   * @throws ResourceNotFoundException if the organization is not found.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  private Organization findAndAuthorizeOrgAccess(UUID targetOrgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    Organization org = organizationRepository.findById(targetOrgId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, targetOrgId)));

    boolean isSuper = actorRoles.contains(RoleType.SUPER);
    boolean isMemberOfOrg = Objects.equals(targetOrgId, actorOrgId);

    if (!isSuper && !isMemberOfOrg) {
      log.warn("Authorization failed: Actor '{}' (Org: {}) cannot access details for Org ID '{}'. Requires SUPER role or membership.",
              actor, actorOrgId, targetOrgId);
      throw new AccessDeniedException("User does not have permission to access this organization's configuration.");
    }
    log.trace("Authorization successful for actor '{}' to access Org ID '{}'", actor, targetOrgId);
    return org;
  }

  /**
   * Finds an organization by ID and checks if the requesting actor has permission to modify its configuration.
   * Access allowed ONLY for SUPER users or ADMIN users belonging to the target organization.
   *
   * @param targetOrgId The UUID of the organization being modified.
   * @param actor       The username of the requesting actor.
   * @param actorOrgId  The organization UUID of the requesting actor.
   * @param actorRoles  The roles of the requesting actor.
   * @return The found {@link Organization} entity.
   * @throws ResourceNotFoundException if the organization is not found.
   * @throws AccessDeniedException     if the actor lacks permission.
   */
  private Organization findAndAuthorizeOrgAdminOrSuperAccess(UUID targetOrgId, String actor, UUID actorOrgId, Set<RoleType> actorRoles) {
    Organization org = organizationRepository.findById(targetOrgId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, targetOrgId)));

    boolean isSuper = actorRoles.contains(RoleType.SUPER);
    boolean isAdminOfThisOrg = actorRoles.contains(RoleType.ADMIN) && Objects.equals(targetOrgId, actorOrgId);

    if (!isSuper && !isAdminOfThisOrg) {
      log.warn("Authorization failed: Actor '{}' (Org: {}, Roles: {}) cannot modify config for Org ID '{}'. Requires SUPER role or ADMIN of the target organization.",
              actor, actorOrgId, actorRoles, targetOrgId);
      throw new AccessDeniedException("User must be a Super User or an Admin of this organization to modify its configuration.");
    }
    log.trace("Authorization successful for actor '{}' to modify config for Org ID '{}'", actor, targetOrgId);
    return org;
  }
}