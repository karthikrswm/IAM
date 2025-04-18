// File: src/main/java/org/example/iam/repository/DatabaseRelyingPartyRegistrationRepository.java
package org.example.iam.repository;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.entity.Organization; // Import Organization for logging context
import org.example.iam.entity.SamlConfig;
import org.example.iam.exception.ConfigurationException;
// Import classes for handling certificates if stored/needed securely
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
// Import our new CredentialService
import org.example.iam.service.CredentialService;
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
 * Uses {@link CredentialService} to load SP signing/encryption credentials from keystores
 * referenced in the configuration.
 * </p>
 * <p>
 * **Security Note:** Relies on the injected {@link CredentialService} and underlying
 * secure storage mechanisms (keystore files, encrypted passwords, potential vault integration)
 * for handling private keys and certificates securely.
 * </p>
 */
@Repository("databaseRelyingPartyRegistrationRepository") // Explicit bean name
@RequiredArgsConstructor
@Slf4j
public class DatabaseRelyingPartyRegistrationRepository implements
        RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> { // Implement Iterable

  private final SamlConfigRepository samlConfigRepository;
  private final CredentialService credentialService;

  /**
   * In-memory cache holding the loaded RelyingPartyRegistration objects.
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
    List<SamlConfig> enabledConfigs = samlConfigRepository.findAll()
            .stream()
            .filter(config -> config.isEnabled() && config.getOrganization() != null)
            .toList();

    if (enabledConfigs.isEmpty()) {
      log.warn("No enabled and valid SAML configurations found in the database.");
      return;
    }

    log.info("Found {} potentially enabled SAML configurations. Building registrations...", enabledConfigs.size());
    int successfullyLoaded = 0;
    for (SamlConfig config : enabledConfigs) {
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
   * Uses metadata URL and attempts to load credentials via {@link CredentialService}.
   * </p>
   *
   * @param config The {@link SamlConfig} entity from the database.
   * @return A configured {@link RelyingPartyRegistration} object.
   * @throws ConfigurationException if essential configuration is missing or invalid, or if credentials cannot be loaded.
   */
  private RelyingPartyRegistration buildRelyingPartyRegistration(SamlConfig config) {
    log.debug("Building RelyingPartyRegistration for SamlConfig ID: {}", config.getId());

    Organization org = config.getOrganization();
    if (org == null) {
      String errorMsg = String.format("SAML config ID %s is not linked to an Organization.", config.getId());
      log.error("Cannot build RelyingPartyRegistration: {}", errorMsg);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")");
    }

    if (!StringUtils.hasText(config.getIdentityProviderMetadataUrl())) {
      String errorMsg = String.format("Identity Provider Metadata URL is required in SamlConfig ID %s for Org ID %s.", config.getId(), org.getId());
      log.error("Cannot build RelyingPartyRegistration: {}", errorMsg);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")");
    }
    if (!StringUtils.hasText(config.getServiceProviderEntityId())) {
      String errorMsg = String.format("Service Provider Entity ID is required in SamlConfig ID %s for Org ID %s.", config.getId(), org.getId());
      log.error("Cannot build RelyingPartyRegistration: {}", errorMsg);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")");
    }


    // 1. Generate the unique registrationId
    String registrationId = generateRegistrationId(org.getId());

    // 2. Load SP Credentials using CredentialService
    Saml2X509Credential spSigningCredential = loadSpSigningCredential(config);
    Saml2X509Credential spDecryptionCredential = loadSpDecryptionCredential(config);
    // Optional: Load IdP verification credential explicitly if needed
    Saml2X509Credential idpVerificationCredential = loadIdpVerificationCredential(config);

    // 3. Use RelyingPartyRegistrations helper to load from metadata URL
    RelyingPartyRegistration.Builder builder;
    try {
      builder = RelyingPartyRegistrations
              .fromMetadataLocation(config.getIdentityProviderMetadataUrl())
              .registrationId(registrationId)
              .entityId(config.getServiceProviderEntityId())
              .assertionConsumerServiceLocation(config.getAssertionConsumerServiceUrl());
    } catch (IllegalArgumentException | IllegalStateException e) {
      String errorMsg = String.format("Failed to load or parse SAML metadata from URL '%s' for config ID %s.", config.getIdentityProviderMetadataUrl(), config.getId());
      log.error(errorMsg, e);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")", e);
    }

    // 4. Apply loaded SP Credentials
    if (spSigningCredential != null) {
      builder.signingX509Credentials(creds -> creds.add(spSigningCredential));
      log.debug("Added SP signing credential for registrationId: {}", registrationId);
    } else if (config.isSignRequests()) {
      String errorMsg = "SAML config for registrationId '" + registrationId + "' requires signing requests, but no SP signing credential was loaded/configured!";
      log.error(errorMsg);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")");
    }

    if (spDecryptionCredential != null) {
      builder.decryptionX509Credentials(creds -> creds.add(spDecryptionCredential));
      log.debug("Added SP decryption credential for registrationId: {}", registrationId);
    }

    // 5. Configure Single Logout (SLO) if URL is provided
    if (StringUtils.hasText(config.getSingleLogoutServiceUrl())) {
      builder.singleLogoutServiceLocation(config.getSingleLogoutServiceUrl());
      builder.singleLogoutServiceResponseLocation(config.getSingleLogoutServiceUrl());
      builder.singleLogoutServiceBinding(Saml2MessageBinding.POST);
      log.debug("Configured SLO endpoint for registrationId: {}", registrationId);
    }

    // 6. Configure Asserting Party (IdP) Details
    builder.assertingPartyDetails(party -> {
      party.wantAuthnRequestsSigned(config.isSignRequests());
      // Add IdP verification credential if loaded explicitly
      if (idpVerificationCredential != null) {
        party.verificationX509Credentials(creds -> creds.add(idpVerificationCredential));
        log.debug("Added explicit IdP verification credential for registrationId: {}", registrationId);
      }
      // Note: wantAssertionsSigned is checked during authentication, not configured here directly in builder
    });

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
    return "saml-org-" + orgId.toString();
  }

  // --- Credential Loading using CredentialService ---

  /**
   * Loads the SP signing credential (private key + public certificate) using CredentialService.
   *
   * @param config The SamlConfig entity.
   * @return The loaded Saml2X509Credential for signing, or null if not configured/found/loadable.
   */
  private Saml2X509Credential loadSpSigningCredential(SamlConfig config) {
    // Use the correct getter methods for the PKCS12 fields
    String path = config.getSpSigningKeystorePath();              // <<< CORRECTED
    String alias = config.getSpSigningKeyAlias();                 // <<< CORRECTED
    String encryptedPasswordRef = config.getSpSigningKeystorePasswordEncrypted(); // <<< CORRECTED

    if (!StringUtils.hasText(path) || !StringUtils.hasText(alias) || !StringUtils.hasText(encryptedPasswordRef)) {
      log.trace("SP Signing credentials not fully configured for SamlConfig ID {}", config.getId());
      return null;
    }
    try {
      log.debug("Loading SP signing credential from ref: {}, alias: {}", path, alias);
      // Pass the encrypted password reference directly to the service
      PrivateKey privateKey = credentialService.loadPrivateKey(path, alias, encryptedPasswordRef);
      X509Certificate certificate = credentialService.loadCertificate(path, alias, encryptedPasswordRef);

      if (privateKey != null && certificate != null) {
        return Saml2X509Credential.signing(privateKey, certificate);
      } else {
        log.error("Failed to load SP signing key or certificate for config ID {}", config.getId());
        return null;
      }
    } catch (Exception e) {
      log.error("Error loading SP signing credential for SamlConfig ID {}: {}", config.getId(), e.getMessage(), e);
      return null;
    }
  }

  /**
   * Loads the SP decryption credential (private key + public certificate) using CredentialService.
   *
   * @param config The SamlConfig entity.
   * @return The loaded Saml2X509Credential for decryption, or null.
   */
  private Saml2X509Credential loadSpDecryptionCredential(SamlConfig config) {
    // Use the correct getter methods for the PKCS12 fields
    String path = config.getSpEncryptionKeystorePath();            // <<< CORRECTED
    String alias = config.getSpEncryptionKeyAlias();               // <<< CORRECTED
    String encryptedPasswordRef = config.getSpEncryptionKeystorePasswordEncrypted(); // <<< CORRECTED

    if (!StringUtils.hasText(path) || !StringUtils.hasText(alias) || !StringUtils.hasText(encryptedPasswordRef)) {
      log.trace("SP Decryption credentials not fully configured for SamlConfig ID {}", config.getId());
      return null;
    }
    try {
      log.debug("Loading SP decryption credential from ref: {}, alias: {}", path, alias);
      PrivateKey privateKey = credentialService.loadPrivateKey(path, alias, encryptedPasswordRef);
      X509Certificate certificate = credentialService.loadCertificate(path, alias, encryptedPasswordRef);

      if (privateKey != null && certificate != null) {
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
      } else {
        log.error("Failed to load SP decryption key or certificate for config ID {}", config.getId());
        return null;
      }
    } catch (Exception e) {
      log.error("Error loading SP decryption credential for SamlConfig ID {}: {}", config.getId(), e.getMessage(), e);
      return null;
    }
  }

  /**
   * Loads the IdP verification certificate explicitly from config using CredentialService.
   *
   * @param config The SamlConfig entity.
   * @return The loaded Saml2X509Credential for verification, or null.
   */
  private Saml2X509Credential loadIdpVerificationCredential(SamlConfig config) {
    // Use the correct getter method for the PEM field
    String certPem = config.getIdpVerificationCertificatePem(); // <<< CORRECTED

    if (!StringUtils.hasText(certPem)) {
      log.trace("Explicit IdP verification certificate not configured for SamlConfig ID {}. Relying on metadata.", config.getId());
      return null;
    }
    try {
      log.debug("Loading explicit IdP verification credential from PEM for config ID {}", config.getId());
      X509Certificate certificate = credentialService.loadCertificateFromPem(certPem); // Use service helper

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