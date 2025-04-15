// File: src/main/java/org/example/iam/repository/DatabaseRelyingPartyRegistrationRepository.java
package org.example.iam.repository;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.entity.Organization; // Import Organization for logging context
import org.example.iam.entity.SamlConfig;
import org.example.iam.exception.ConfigurationException;
// Import classes for handling certificates if stored/needed securely
// import java.security.cert.X509Certificate;
// import java.security.PrivateKey;
// import org.example.iam.service.CertificateService; // Example service for secure handling
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations; // Utility for metadata loading
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;


/**
 * Custom implementation of {@link RelyingPartyRegistrationRepository} that loads SAML 2.0
 * Service Provider (SP) configurations dynamically from the database via {@link SamlConfigRepository}.
 * <p>
 * This enables per-{@link Organization} SAML configurations, allowing the application to act as an SP
 * interacting with different Identity Providers (IdPs) based on the organization context.
 * Configurations are loaded at startup and cached in memory.
 * </p>
 * <p>
 * It leverages {@link RelyingPartyRegistrations#fromMetadataLocation(String)} to simplify
 * configuration by fetching IdP details dynamically from a metadata URL when available.
 * </p>
 * <p>
 * **Security Note:** Handling of SP signing/encryption keys and certificates requires secure
 * implementation. The current placeholder fields in {@link SamlConfig} and the build logic here assume
 * insecure storage or require integration with a secure service (e.g., {@code CertificateService})
 * to load credentials. Production systems MUST implement secure key/certificate management.
 * </p>
 */
@Repository("databaseRelyingPartyRegistrationRepository") // Explicit bean name
@RequiredArgsConstructor
@Slf4j
public class DatabaseRelyingPartyRegistrationRepository implements
        RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> { // Implement Iterable

  private final SamlConfigRepository samlConfigRepository;
  // Inject services needed for handling certificates/keys if stored securely
  // Example: Assuming a service that can load certs/keys based on stored references/paths
  // private final CertificateService certificateService;

  /**
   * In-memory cache holding the loaded RelyingPartyRegistration objects.
   * Key: Dynamically generated registrationId (e.g., "saml-orgUUID").
   * Value: The corresponding RelyingPartyRegistration object.
   * Uses ConcurrentHashMap for thread safety.
   */
  private final Map<String, RelyingPartyRegistration> relyingPartyRegistrations = new ConcurrentHashMap<>();

  /**
   * Initializes the repository by loading all enabled SAML configurations from the database
   * during application startup. Builds {@link RelyingPartyRegistration} objects and populates
   * the in-memory cache.
   */
  @PostConstruct
  public void loadRelyingPartyRegistrations() {
    log.info("Loading SAML relying party registrations from database...");
    // Ensure you have a findByEnabledTrue method or filter here in a real application
    List<SamlConfig> enabledConfigs = samlConfigRepository.findAll()
            .stream()
            .filter(config -> config.isEnabled() && config.getOrganization() != null) // Filter enabled and valid configs
            .toList();

    if (enabledConfigs.isEmpty()) {
      log.warn("No enabled and valid SAML configurations found in the database.");
      return;
    }

    log.info("Found {} potentially enabled SAML configurations. Building registrations...", enabledConfigs.size());
    int successfullyLoaded = 0;
    for (SamlConfig config : enabledConfigs) {
      // Org null check already done by filter above
      Organization org = config.getOrganization();
      try {
        RelyingPartyRegistration registration = buildRelyingPartyRegistration(config);
        if (registration != null) {
          String registrationId = registration.getRegistrationId();
          this.relyingPartyRegistrations.put(registrationId, registration);
          log.info("-> Loaded SAML relying party registration: ID='{}' (SP EntityID: '{}', Org: '{}')",
                  registrationId,
                  config.getServiceProviderEntityId(),
                  org.getOrgName());
          successfullyLoaded++;
        }
      } catch (Exception e) {
        log.error("!!! Failed to build SAML relying party registration for DB config ID {}. OrgID: {}. Error: {} !!!",
                config.getId(), org.getId(), e.getMessage(), e);
        // Continue loading others, but log critical failure
      }
    }
    log.info("Finished loading SAML configurations. Successfully loaded {} registration(s).", successfullyLoaded);
  }

  /**
   * Finds a {@link RelyingPartyRegistration} by its unique registration ID.
   * Called by Spring Security during the SAML 2.0 flow.
   *
   * @param registrationId The unique ID for the relying party registration (e.g., "saml-orgUUID").
   * @return The {@link RelyingPartyRegistration}, or {@code null} if not found in the cache.
   */
  @Override
  public RelyingPartyRegistration findByRegistrationId(String registrationId) {
    log.trace("Looking up RelyingPartyRegistration for registrationId: {}", registrationId);
    RelyingPartyRegistration registration = this.relyingPartyRegistrations.get(registrationId);
    if (registration == null) {
      log.warn("RelyingPartyRegistration not found for registrationId: {}", registrationId);
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
    return Collections.unmodifiableCollection(this.relyingPartyRegistrations.values()).iterator();
  }

  /**
   * Helper method to construct a Spring Security {@link RelyingPartyRegistration} object
   * from the application's {@link SamlConfig} entity.
   * <p>
   * Uses {@link RelyingPartyRegistrations#fromMetadataLocation(String)} for simplified
   * configuration when an IdP metadata URL is available. Handles SP-specific settings
   * and placeholders for credential loading.
   * </p>
   *
   * @param config The {@link SamlConfig} entity from the database.
   * @return A configured {@link RelyingPartyRegistration} object.
   * @throws ConfigurationException if essential configuration (like IdP metadata URL or SP entity ID) is missing or invalid.
   */
  private RelyingPartyRegistration buildRelyingPartyRegistration(SamlConfig config) {
    log.debug("Building RelyingPartyRegistration for SamlConfig ID: {}", config.getId());

    // Ensure Org exists (checked earlier, but good practice)
    Organization org = config.getOrganization();
    if (org == null) {
      log.error("Cannot build RelyingPartyRegistration: SamlConfig ID {} is not linked to an Organization.", config.getId());
      throw new ConfigurationException("SAML config " + config.getId() + " is orphaned.");
    }

    // IdP Metadata URL is the preferred configuration method.
    if (!StringUtils.hasText(config.getIdentityProviderMetadataUrl())) {
      log.error("Cannot build RelyingPartyRegistration for Org ID {}: Identity Provider Metadata URL is required in SamlConfig ID {}.",
              org.getId(), config.getId());
      // IdP metadata URL is crucial for RelyingPartyRegistrations utility
      throw new ConfigurationException("IdP Metadata URL is required for SAML config " + config.getId());
    }
    if (!StringUtils.hasText(config.getServiceProviderEntityId())) {
      log.error("Cannot build RelyingPartyRegistration for Org ID {}: Service Provider Entity ID is required in SamlConfig ID {}.",
              org.getId(), config.getId());
      throw new ConfigurationException("SP Entity ID is required for SAML config " + config.getId());
    }


    // 1. Generate the unique registrationId
    String registrationId = generateRegistrationId(org.getId());

    // 2. Load SP Credentials (Signing and Decryption/Encryption) - **PLACEHOLDER**
    // This requires a secure implementation (e.g., using CertificateService)
    Saml2X509Credential spSigningCredential = loadSpSigningCredential(config); // Replace with secure loading
    Saml2X509Credential spDecryptionCredential = loadSpDecryptionCredential(config); // Replace with secure loading

    // 3. Use RelyingPartyRegistrations helper to load from metadata URL
    // This utility fetches and parses the metadata to configure IdP details.
    RelyingPartyRegistration.Builder builder = RelyingPartyRegistrations
            .fromMetadataLocation(config.getIdentityProviderMetadataUrl())
            .registrationId(registrationId)
            // --- Service Provider (Our Application) Configuration ---
            .entityId(config.getServiceProviderEntityId()) // Our SP entity ID for this Org
            .assertionConsumerServiceLocation(config.getAssertionConsumerServiceUrl()); // Our ACS URL

    // Add SP Signing credentials if configured and loaded
    if (spSigningCredential != null) {
      builder.signingX509Credentials(creds -> creds.add(spSigningCredential));
      log.debug("Added SP signing credential for registrationId: {}", registrationId);
    } else if (config.isSignRequests()) {
      // If config demands signing but no credential found, log a warning or throw error
      log.warn("SAML config for registrationId '{}' requires signing requests, but no SP signing credential was loaded!", registrationId);
      // Optionally throw: throw new ConfigurationException("Missing SP signing credential for " + registrationId);
    }

    // Add SP Decryption credentials if available/needed
    // (Encryption is less common than signing, depends on IdP capability/requirements)
    if (spDecryptionCredential != null) {
      builder.decryptionX509Credentials(creds -> creds.add(spDecryptionCredential));
      log.debug("Added SP decryption credential for registrationId: {}", registrationId);
    }

    // Configure Single Logout (SLO) if URL is provided
    if (StringUtils.hasText(config.getSingleLogoutServiceUrl())) {
      builder.singleLogoutServiceLocation(config.getSingleLogoutServiceUrl());
      // Typically, response location is same as request location for SLO
      builder.singleLogoutServiceResponseLocation(config.getSingleLogoutServiceUrl());
      // Common bindings are POST or Redirect, configure as needed
      builder.singleLogoutServiceBinding(Saml2MessageBinding.POST);
      log.debug("Configured SLO endpoint for registrationId: {}", registrationId);
    }

    // --- Asserting Party (Identity Provider) Details ---
    // Customize how we interact with the IdP loaded from metadata.
    builder.assertingPartyDetails(party -> party
                    // Should the IdP expect AuthnRequests signed by us? Matches config.isSignRequests().
                    .wantAuthnRequestsSigned(config.isSignRequests())
            // Configure other IdP details if needed (e.g., required NameID format, verification certs if not in metadata)
            // .verificationX509Credentials(...) // If IdP signing cert needs explicit configuration
            // .singleSignOnServiceLocation(...) // Override if needed
            // .singleSignOnServiceBinding(...) // Override if needed
    );

    log.debug("Successfully built RelyingPartyRegistration for registrationId: {}", registrationId);
    return builder.build();
  }


  /**
   * Generates a unique and URL-safe registration ID based on the Organization's UUID.
   * Example: "saml-org-a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
   *
   * @param orgId The organization's UUID.
   * @return A unique string suitable for use as a registration ID.
   */
  private String generateRegistrationId(UUID orgId) {
    // Using a simple prefix, ensure it's distinct from OAuth2 if needed
    return "saml-org-" + orgId.toString();
  }

  // --- Placeholder Methods for Secure Credential Loading ---
  // Replace these with actual secure loading logic (e.g., from Vault, KMS, encrypted DB field)

  /**
   * **PLACEHOLDER:** Loads the SP signing credential (private key + public certificate).
   * Replace with secure loading logic (e.g., from vault, file system, CertificateService).
   *
   * @param config The SamlConfig entity containing references or encrypted data.
   * @return The loaded Saml2X509Credential for signing, or null if not configured/found.
   */
  private Saml2X509Credential loadSpSigningCredential(SamlConfig config) {
    log.warn("[Security Placeholder] Loading SP signing credential for SamlConfig ID {} is not securely implemented!", config.getId());
    // Example:
    // if (StringUtils.hasText(config.getSpSigningKeyRef()) && StringUtils.hasText(config.getSpSigningCertRef())) {
    //     try {
    //         PrivateKey privateKey = certificateService.loadPrivateKey(config.getSpSigningKeyRef());
    //         X509Certificate certificate = certificateService.loadCertificate(config.getSpSigningCertRef());
    //         return Saml2X509Credential.signing(privateKey, certificate);
    //     } catch (Exception e) {
    //         log.error("Failed to load SP signing credential for SamlConfig ID {}", config.getId(), e);
    //         throw new ConfigurationException("Failed to load SP signing credential", e);
    //     }
    // }
    return null; // Return null if not configured or loading fails
  }

  /**
   * **PLACEHOLDER:** Loads the SP decryption credential (private key + public certificate).
   * Replace with secure loading logic. Needed if IdP encrypts assertions.
   *
   * @param config The SamlConfig entity.
   * @return The loaded Saml2X509Credential for decryption, or null.
   */
  private Saml2X509Credential loadSpDecryptionCredential(SamlConfig config) {
    log.warn("[Security Placeholder] Loading SP decryption credential for SamlConfig ID {} is not securely implemented!", config.getId());
    // Similar secure loading logic as signing credential
    return null;
  }

}