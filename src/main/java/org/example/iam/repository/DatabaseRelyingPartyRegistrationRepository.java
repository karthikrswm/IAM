// File: src/main/java/org/example/iam/repository/DatabaseRelyingPartyRegistrationRepository.java
package org.example.iam.repository;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages; // Used in ConfigurationException
import org.example.iam.entity.Organization;
import org.example.iam.entity.SamlConfig;
import org.example.iam.exception.ConfigurationException;
import org.example.iam.service.CredentialService; // Required for loading credentials
import org.springframework.security.saml2.core.Saml2Error; // Required for Saml2Exception catch block
import org.springframework.security.saml2.core.Saml2ErrorCodes; // Used in exception handling potentially
import org.springframework.security.saml2.Saml2Exception; // Specific exception for metadata loading issues
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations; // Utility used
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding; // Required import
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Custom implementation of {@link RelyingPartyRegistrationRepository} that loads SAML 2.0 SP/IdP
 * configurations dynamically from the database via {@link SamlConfigRepository}.
 * <p>
 * Attempts to load IdP details from metadata URL first, falling back to manually configured
 * fields from the {@link SamlConfig} entity. Uses {@link CredentialService} to load SP credentials
 * (signing/encryption keys) from keystores, supporting separate key alias passwords.
 * </p>
 * <p>
 * Configurations are cached in memory upon application startup.
 * </p>
 */
@Repository("databaseRelyingPartyRegistrationRepository") // Explicit bean name
@RequiredArgsConstructor
@Slf4j
public class DatabaseRelyingPartyRegistrationRepository implements
        RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

  private final SamlConfigRepository samlConfigRepository;
  private final CredentialService credentialService;

  /**
   * In-memory cache holding the loaded RelyingPartyRegistration objects.
   * Key: Dynamically generated registrationId (e.g., "saml-org-UUID").
   * Value: The corresponding RelyingPartyRegistration object.
   * Uses ConcurrentHashMap for thread safety.
   */
  private final Map<String, RelyingPartyRegistration> registrationCache = new ConcurrentHashMap<>();

  /**
   * Initializes the repository by loading all enabled SAML configurations
   * from the database during application startup.
   * Builds {@link RelyingPartyRegistration} objects and populates the in-memory cache.
   * Logs errors encountered during loading but continues with other configurations.
   */
  @PostConstruct
  @Transactional(readOnly = true)
  public void loadRegistrations() {
    log.info("Loading SAML Relying Party Registrations from database...");
    int count = 0;
    // Fetch all configs marked as enabled in the DB
    List<SamlConfig> enabledConfigs = samlConfigRepository.findByEnabledTrue();

    if (enabledConfigs.isEmpty()) {
      log.warn("No enabled SAML configurations found in the database to load.");
      return;
    }

    log.info("Found {} potentially enabled SAML configurations. Building registrations...", enabledConfigs.size());
    for (SamlConfig config : enabledConfigs) {
      if (config.getOrganization() == null) {
        log.error("!!! Skipping SAML config ID '{}': It is not linked to an Organization. !!!", config.getId());
        continue; // Skip configs not linked to an org
      }
      try {
        // Attempt to build the full registration object from the DB config
        RelyingPartyRegistration registration = buildRelyingPartyRegistration(config);
        if (registration != null) {
          // Store the successfully built registration in the cache
          registrationCache.put(registration.getRegistrationId(), registration);
          log.info(" -> Loaded SAML registration: ID='{}', SP_EntityID='{}', IdP_EntityID='{}'",
                  registration.getRegistrationId(),
                  registration.getEntityId(),
                  registration.getAssertingPartyDetails().getEntityId()); // Log key identifiers
          count++;
        }
        // buildRelyingPartyRegistration throws exceptions on critical build failures
      } catch (Exception e) {
        // Catch exceptions during build process for a specific config
        log.error("!!! Failed to build/load SAML registration for SamlConfig ID '{}' (Org ID '{}'): {} !!!",
                config.getId(), config.getOrganization().getId(), e.getMessage());
        // Log stack trace at DEBUG level if needed
        log.debug("Stack trace for SAML registration build failure:", e);
        // Continue loading other configurations
      }
    }
    log.info("Finished loading SAML configurations. Successfully loaded {} registration(s).", count);
  }

  /**
   * Finds a {@link RelyingPartyRegistration} by its unique registration ID from the cache.
   * This method is called by Spring Security during the SAML 2.0 flow.
   * Currently does not dynamically reload from DB if not found in cache.
   *
   * @param id The unique ID for the relying party registration (e.g., "saml-org-UUID").
   * @return The {@link RelyingPartyRegistration}, or {@code null} if not found in the cache.
   */
  @Override
  public RelyingPartyRegistration findByRegistrationId(String id) {
    log.trace("Looking up RelyingPartyRegistration for registrationId: {}", id);
    RelyingPartyRegistration registration = registrationCache.get(id);
    if (registration == null) {
      // Optional: Could add logic here to query SamlConfigRepository by registration ID
      // (would need a way to parse orgId from registrationId) and call buildRelyingPartyRegistration
      // on demand if not found in cache, but this adds complexity.
      // For now, rely on PostConstruct loading.
      log.warn("RelyingPartyRegistration not found in cache for registrationId: {}. Dynamic loading not implemented.", id);
    }
    return registration;
  }

  /**
   * Provides an iterator over the cached {@link RelyingPartyRegistration} objects.
   * Required by {@link Iterable}.
   *
   * @return An iterator over the loaded relying party registrations.
   */
  @Override
  public Iterator<RelyingPartyRegistration> iterator() {
    return Collections.unmodifiableCollection(this.registrationCache.values()).iterator();
  }

  /**
   * Builds a RelyingPartyRegistration from a SamlConfig entity.
   * Attempts to load IdP details from metadata URL first, falling back to manual configuration fields.
   * Loads credentials using CredentialService.
   *
   * @param config The {@link SamlConfig} entity containing all necessary configuration.
   * @return A configured {@link RelyingPartyRegistration} object ready for use.
   * @throws ConfigurationException if the configuration is inconsistent or essential parts are missing.
   */
  private RelyingPartyRegistration buildRelyingPartyRegistration(SamlConfig config) {
    if (config.getOrganization() == null) {
      throw new ConfigurationException("SamlConfig ID " + config.getId() + " is not linked to an Organization.");
    }
    Organization org = config.getOrganization();
    String registrationId = generateRegistrationId(org.getId()); // Use helper
    log.debug("Building RelyingPartyRegistration for registrationId '{}' (Org: '{}')", registrationId, org.getOrgName());

    RelyingPartyRegistration.Builder builder;
    boolean loadedFromMetadata = false;

    // --- 1. Attempt to load base configuration from IdP Metadata URL ---
    if (StringUtils.hasText(config.getIdentityProviderMetadataUrl())) {
      log.debug("Attempting to load IdP configuration from metadata URL: {}", config.getIdentityProviderMetadataUrl());
      try {
        // Use Spring utility to fetch and parse metadata, setting IdP details on the builder
        builder = RelyingPartyRegistrations
                .fromMetadataLocation(config.getIdentityProviderMetadataUrl())
                .registrationId(registrationId); // Set our registration ID
        log.info("Successfully loaded base configuration from metadata URL for '{}'.", registrationId);
        loadedFromMetadata = true;
      } catch (IllegalArgumentException | Saml2Exception e) {
        // Log failure clearly but allow fallback to manual config
        log.warn("Failed to load or parse SAML metadata from URL '{}' for config ID {}. Error: {}. Attempting manual config fallback.",
                config.getIdentityProviderMetadataUrl(), config.getId(), e.getMessage());
        builder = RelyingPartyRegistration.withRegistrationId(registrationId);
      } catch (Exception e) {
        log.error("Unexpected error loading SAML metadata from URL '{}' for config ID {}: {}",
                config.getIdentityProviderMetadataUrl(), config.getId(), e.getMessage(), e);
        throw new ConfigurationException("Unexpected error processing IdP metadata URL", e);
      }
    } else {
      // No metadata URL, proceed with manual configuration
      log.info("No IdP Metadata URL provided for registrationId '{}'. Using manual configuration.", registrationId);
      builder = RelyingPartyRegistration.withRegistrationId(registrationId);
    }

    // --- 2. Apply/Override SP details with configuration from SamlConfig Entity ---
    log.debug("Applying SP configuration details from database for '{}'", registrationId);
    if (!StringUtils.hasText(config.getServiceProviderEntityId())) { throw new ConfigurationException("SP Entity ID missing for " + registrationId); }
    if (!StringUtils.hasText(config.getAssertionConsumerServiceUrl())) { throw new ConfigurationException("SP ACS URL missing for " + registrationId); }

    builder.entityId(config.getServiceProviderEntityId());
    builder.assertionConsumerServiceLocation(config.getAssertionConsumerServiceUrl());
    builder.assertionConsumerServiceBinding(Saml2MessageBinding.POST); // Defaulting to POST

    // Load and apply SP Credentials (Signing/Decryption) using helpers below
    Saml2X509Credential signingCredential = loadSpSigningCredential(config);
    Saml2X509Credential decryptionCredential = loadSpDecryptionCredential(config);
    builder.signingX509Credentials(c -> { if (signingCredential != null) c.add(signingCredential); });
    builder.decryptionX509Credentials(c -> { if (decryptionCredential != null) c.add(decryptionCredential); });

    // --- 3. Configure IdP (Asserting Party) Details ---
    // Use effectively final variable for lambda access
    final boolean wasLoadedFromMetadata = loadedFromMetadata;
    builder.assertingPartyDetails(party -> {
      // If NOT loaded from metadata, populate from manual fields
      if (!wasLoadedFromMetadata) {
        log.debug("Configuring AssertingPartyDetails manually for '{}'.", registrationId);
        // Validate that required manual fields are present
        if (!StringUtils.hasText(config.getIdentityProviderEntityId()) ||
                !StringUtils.hasText(config.getSingleSignOnServiceUrl()) ||
                config.getSingleSignOnServiceBinding() == null) {
          throw new ConfigurationException(
                  String.format("Manual SAML config incomplete for registration '%s': IdP Entity ID, SSO URL, and SSO Binding required when metadata fails/missing.", registrationId)
          );
        }
        party.entityId(config.getIdentityProviderEntityId());
        party.singleSignOnServiceLocation(config.getSingleSignOnServiceUrl());
        party.singleSignOnServiceBinding(config.getSingleSignOnServiceBinding());
      } else {
        log.debug("AssertingPartyDetails primarily configured from metadata for '{}'.", registrationId);
      }

      // Always apply WantAuthnRequestsSigned from our config (SP's preference)
      party.wantAuthnRequestsSigned(config.isSignRequests());

      // Load and apply explicit verification cert from PEM, potentially overriding metadata
      Saml2X509Credential verificationCredential = loadIdpVerificationCredential(config);
      if (verificationCredential != null) {
        party.verificationX509Credentials(c -> {
          c.clear(); // Clear any certs loaded from metadata
          c.add(verificationCredential); // Add the explicit one from DB config
        });
        log.debug("Applied explicit IdP verification credential for '{}'", registrationId);
      } else if (!wasLoadedFromMetadata) {
        // If no metadata AND no explicit cert, verification will fail later. Log error.
        log.error("Cannot configure IdP verification credential for '{}': Neither metadata URL nor explicit certificate PEM provided.", registrationId);
        throw new ConfigurationException("IdP verification credential configuration is missing for registration " + registrationId);
      }
      // Note: If metadata *was* loaded and contained certs, and no explicit PEM is provided,
      // the metadata certs will be used implicitly by the builder.
    });

    // --- 4. Configure SLO if needed ---
    if (StringUtils.hasText(config.getSingleLogoutServiceUrl())) {
      builder.singleLogoutServiceLocation(config.getSingleLogoutServiceUrl());
      // Determine binding: use value from config if set, otherwise default to POST
      Saml2MessageBinding sloBinding = config.getSingleSignOnServiceBinding() != null ? config.getSingleSignOnServiceBinding() : Saml2MessageBinding.POST; // Reuse SSO binding or default
      // TODO: Add a specific idp_slo_binding field to SamlConfig if needed
      builder.singleLogoutServiceBinding(sloBinding);
      // Assume response location is same as request location for SLO
      builder.singleLogoutServiceResponseLocation(config.getSingleLogoutServiceUrl());
      log.debug("Configured SLO endpoint for '{}'", registrationId);
    }

    // --- 5. Build the final registration ---
    try {
      RelyingPartyRegistration registration = builder.build();
      // Final validation - ensure critical IdP details were set either via metadata or manually
      if (registration.getAssertingPartyDetails() == null ||
              !StringUtils.hasText(registration.getAssertingPartyDetails().getEntityId()) ||
              !StringUtils.hasText(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation())) {
        throw new ConfigurationException("Failed to build valid AssertingPartyDetails (missing IdP Entity ID or SSO URL) for registration " + registrationId);
      }
      log.debug("Successfully built RelyingPartyRegistration for registrationId: {}", registrationId);
      return registration;
    } catch (Exception e) {
      log.error("Error during final build of RelyingPartyRegistration for '{}': {}", registrationId, e.getMessage(), e);
      // Wrap specific builder exceptions if needed
      throw new ConfigurationException("Failed to build final RelyingPartyRegistration for " + registrationId, e);
    }
  }

  /**
   * Generates the standard registration ID for a SAML configuration based on Organization ID.
   * Format: "saml-org-{organizationId}"
   *
   * @param orgId The UUID of the organization.
   * @return The generated registration ID string.
   */
  public String generateRegistrationId(UUID orgId) {
    if (orgId == null) {
      throw new IllegalArgumentException("Organization ID cannot be null for generating SAML registration ID");
    }
    return "saml-org-" + orgId.toString();
  }

  // --- Credential Loading Helpers (using separate key passwords) ---

  private Saml2X509Credential loadSpSigningCredential(SamlConfig config) {
    String path = config.getSpSigningKeystorePath();
    String alias = config.getSpSigningKeyAlias();
    String keystorePasswordRef = config.getSpSigningKeystorePasswordEncrypted();
    String keyPasswordRef = config.getSpSigningKeyPasswordEncrypted(); // Get key password ref

    if (!StringUtils.hasText(path) || !StringUtils.hasText(alias) || !StringUtils.hasText(keystorePasswordRef)) {
      log.trace("SP Signing credentials not fully configured for SamlConfig ID {}", config.getId());
      return null;
    }
    try {
      log.debug("Loading SP signing credential from ref: {}, alias: {}", path, alias);
      PrivateKey privateKey = credentialService.loadPrivateKey(path, alias, keystorePasswordRef, keyPasswordRef); // Pass both refs
      X509Certificate certificate = credentialService.loadCertificate(path, alias, keystorePasswordRef);

      if (privateKey != null && certificate != null) {
        return Saml2X509Credential.signing(privateKey, certificate);
      } else {
        log.error("SP Signing private key or certificate was null for config ID {}", config.getId());
        return null;
      }
    } catch (Exception e) {
      log.error("Error loading SP signing credential for SamlConfig ID {}: {}", config.getId(), e.getMessage(), e);
      return null;
    }
  }

  private Saml2X509Credential loadSpDecryptionCredential(SamlConfig config) {
    String path = config.getSpEncryptionKeystorePath();
    String alias = config.getSpEncryptionKeyAlias();
    String keystorePasswordRef = config.getSpEncryptionKeystorePasswordEncrypted();
    String keyPasswordRef = config.getSpEncryptionKeyPasswordEncrypted(); // Get key password ref

    if (!StringUtils.hasText(path) || !StringUtils.hasText(alias) || !StringUtils.hasText(keystorePasswordRef)) {
      log.trace("SP Decryption credentials not fully configured for SamlConfig ID {}", config.getId());
      return null;
    }
    try {
      log.debug("Loading SP decryption credential from ref: {}, alias: {}", path, alias);
      PrivateKey privateKey = credentialService.loadPrivateKey(path, alias, keystorePasswordRef, keyPasswordRef); // Pass both refs
      X509Certificate certificate = credentialService.loadCertificate(path, alias, keystorePasswordRef);

      if (privateKey != null && certificate != null) {
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
      } else {
        log.error("SP Decryption private key or certificate was null for config ID {}", config.getId());
        return null;
      }
    } catch (Exception e) {
      log.error("Error loading SP decryption credential for SamlConfig ID {}: {}", config.getId(), e.getMessage(), e);
      return null;
    }
  }

  private Saml2X509Credential loadIdpVerificationCredential(SamlConfig config) {
    String certPem = config.getIdpVerificationCertificatePem();
    if (!StringUtils.hasText(certPem)) {
      log.trace("No explicit IdP verification certificate PEM configured for SamlConfig ID {}.", config.getId());
      return null; // No explicit cert provided
    }
    try {
      log.debug("Loading explicit IdP verification credential from PEM for config ID {}", config.getId());
      X509Certificate certificate = credentialService.loadCertificateFromPem(certPem);
      if (certificate != null) {
        return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
      } else {
        log.error("Failed to load explicit IdP verification certificate from PEM for config ID {}", config.getId());
        return null;
      }
    } catch (Exception e) {
      log.error("Error loading explicit IdP verification credential for SamlConfig ID {}: {}", config.getId(), e.getMessage(), e);
      return null;
    }
  }
}