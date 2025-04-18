// File: src/main/java/org/example/iam/repository/DatabaseClientRegistrationRepository.java
package org.example.iam.repository;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.entity.Oauth2Config;
import org.example.iam.entity.Organization; // Import Organization for Org Name logging
import org.example.iam.exception.ConfigurationException; // Import exception
// Import EncryptionService
import org.example.iam.service.EncryptionService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Custom implementation of {@link ClientRegistrationRepository} that loads OAuth 2.0 client
 * configurations dynamically from the database via {@link Oauth2ConfigRepository}.
 * <p>
 * This allows each {@link Organization} to have its own distinct OAuth 2.0 settings
 * for providers like Google, GitHub, Okta, etc. Registrations are loaded at application
 * startup (via {@link PostConstruct @PostConstruct}) and cached in memory for efficient lookup
 * during OAuth 2.0 authentication flows.
 * </p>
 * <p>
 * The {@code registrationId} used by Spring Security is generated dynamically based on the
 * provider name and organization ID (e.g., "google-a1b2c3d4...").
 * </p>
 * <p>
 * **Security Note:** Uses the injected {@link EncryptionService} to decrypt the
 * stored {@code clientSecretEncrypted} field before building the {@link ClientRegistration}.
 * The encryption key itself MUST be managed securely outside the application code.
 * </p>
 */
@Repository("databaseClientRegistrationRepository") // Explicit bean name for clarity/injection
@RequiredArgsConstructor
@Slf4j
public class DatabaseClientRegistrationRepository implements ClientRegistrationRepository,
        Iterable<ClientRegistration> { // Implement Iterable for discovery

  private final Oauth2ConfigRepository oauth2ConfigRepository;
  private final EncryptionService encryptionService;

  /**
   * In-memory cache holding the loaded ClientRegistration objects.
   * Key: Dynamically generated registrationId (e.g., "google-orgUUID").
   * Value: The corresponding ClientRegistration object.
   * Uses ConcurrentHashMap for thread safety.
   */
  private final Map<String, ClientRegistration> clientRegistrations = new ConcurrentHashMap<>();

  /**
   * Initializes the repository by loading all enabled OAuth 2.0 configurations
   * from the database during application startup.
   * Builds {@link ClientRegistration} objects and populates the in-memory cache.
   */
  @PostConstruct
  public void loadClientRegistrations() {
    log.info("Loading OAuth2 client registrations from database...");
    List<Oauth2Config> enabledConfigs = oauth2ConfigRepository.findAll()
            .stream()
            .filter(config -> config.isEnabled() && config.getOrganization() != null) // Ensure enabled and linked to an Org
            .toList();

    if (enabledConfigs.isEmpty()) {
      log.warn("No enabled and valid OAuth2 configurations found in the database.");
      return;
    }

    log.info("Found {} potentially enabled OAuth2 configurations. Building registrations...", enabledConfigs.size());
    int successfullyLoaded = 0;
    for (Oauth2Config config : enabledConfigs) {
      try {
        ClientRegistration registration = buildClientRegistration(config);
        if (registration != null) {
          String registrationId = registration.getRegistrationId();
          this.clientRegistrations.put(registrationId, registration);
          log.info("-> Loaded OAuth2 client registration: ID='{}' (Provider: {}, Org: '{}')",
                  registrationId,
                  config.getProvider(),
                  config.getOrganization().getOrgName()); // Log Org name for context
          successfullyLoaded++;
        }
      } catch (Exception e) {
        log.error("!!! Failed to build OAuth2 client registration for DB config ID {}. OrgID: {}. Error: {} !!!",
                config.getId(),
                config.getOrganization() != null ? config.getOrganization().getId() : "N/A",
                e.getMessage(), e);
      }
    }
    log.info("Finished loading OAuth2 configurations. Successfully loaded {} registration(s).", successfullyLoaded);
  }

  /**
   * Finds a {@link ClientRegistration} by its unique registration ID.
   * This method is called by Spring Security during the OAuth 2.0 flow.
   *
   * @param registrationId The unique ID for the client registration (e.g., "google-orgUUID").
   * @return The {@link ClientRegistration}, or {@code null} if not found in the cache.
   */
  @Override
  public ClientRegistration findByRegistrationId(String registrationId) {
    log.trace("Looking up ClientRegistration for registrationId: {}", registrationId);
    ClientRegistration registration = this.clientRegistrations.get(registrationId);
    if (registration == null) {
      log.warn("ClientRegistration not found for registrationId: {}", registrationId);
    }
    return registration;
  }

  /**
   * Provides an iterator over the cached {@link ClientRegistration} objects.
   * Required by {@link Iterable}.
   *
   * @return An iterator over the loaded client registrations.
   */
  @Override
  public Iterator<ClientRegistration> iterator() {
    return Collections.unmodifiableCollection(this.clientRegistrations.values()).iterator();
  }

  /**
   * Helper method to construct a Spring Security {@link ClientRegistration} object
   * from the application's {@link Oauth2Config} entity. Decrypts the client secret.
   *
   * @param config The {@link Oauth2Config} entity from the database.
   * @return A configured {@link ClientRegistration} object, or null if construction fails.
   * @throws ConfigurationException if essential configuration is missing or invalid, or decryption fails.
   */
  private ClientRegistration buildClientRegistration(Oauth2Config config) {
    log.debug("Building ClientRegistration for Oauth2Config ID: {}", config.getId());

    if (config.getOrganization() == null) {
      String errorMsg = String.format("Oauth2Config ID %s is not linked to an Organization.", config.getId());
      log.error(errorMsg);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")");
    }
    Organization org = config.getOrganization();

    // 1. Generate the unique registrationId for Spring Security
    String registrationId = generateRegistrationId(config.getProvider(), org.getId());

    // 2. Handle Client Secret (Decrypt stored secret)
    String clientSecret;
    // *** Verify this getter call matches the field name 'clientSecretEncrypted' in Oauth2Config ***
    String encryptedSecret = config.getClientSecretEncrypted(); // <<< THE PROBLEMATIC LINE?

    if (!StringUtils.hasText(encryptedSecret)) {
      String errorMsg = String.format("Encrypted client secret is missing for OAuth2 config ID %s. Registration cannot be built.", config.getId());
      log.error("FATAL: {}", errorMsg);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")");
    }

    try {
      // Decrypt the secret using the injected service
      clientSecret = encryptionService.decrypt(encryptedSecret);
      if (!StringUtils.hasText(clientSecret)) {
        throw new ConfigurationException("Decrypted client secret is empty for config ID " + config.getId());
      }
      log.trace("Successfully decrypted client secret for config ID {}", config.getId());
    } catch (Exception e) {
      String errorMsg = String.format("Failed to decrypt client secret for OAuth2 config ID %s", config.getId());
      log.error("FATAL: {}. Check application encryption key and ciphertext validity.", errorMsg, e);
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + errorMsg + ")", e);
    }


    // 3. Use ClientRegistration builder
    ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
            .clientId(config.getClientId())
            .clientSecret(clientSecret) // Use the DECRYPTED secret
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(StringUtils.hasText(config.getRedirectUriTemplate())
                    ? config.getRedirectUriTemplate()
                    : "{baseUrl}/login/oauth2/code/{registrationId}") // Default pattern
            .authorizationUri(config.getAuthorizationUri())
            .tokenUri(config.getTokenUri())
            .userInfoUri(config.getUserInfoUri())
            .jwkSetUri(config.getJwkSetUri())
            .scope(parseScopes(config.getScopes()))
            .userNameAttributeName(StringUtils.hasText(config.getUserNameAttributeName())
                    ? config.getUserNameAttributeName()
                    : IdTokenClaimNames.SUB)
            .clientName(config.getProvider() + " (" + org.getOrgName() + ")");


    log.debug("Successfully built ClientRegistration for registrationId: {}", registrationId);
    return builder.build();
  }

  /**
   * Generates a unique and URL-safe registration ID for Spring Security.
   * Combines the provider name and organization UUID.
   * Example: "google-a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
   *
   * @param provider The provider identifier (e.g., "google").
   * @param orgId    The organization's UUID.
   * @return A unique string suitable for use as a registration ID.
   */
  private String generateRegistrationId(String provider, UUID orgId) {
    String safeProvider = provider.toLowerCase().replaceAll("[^a-z0-9\\-]", "-");
    return safeProvider + "-" + orgId.toString();
  }

  /**
   * Parses a comma-separated scope string from the configuration into a Set of strings.
   * Handles null or empty input and trims whitespace. Defaults to common OIDC scopes if none provided.
   *
   * @param scopeString The comma-separated scope string (e.g., "openid,profile,email").
   * @return A Set of scope strings.
   */
  private Set<String> parseScopes(String scopeString) {
    if (!StringUtils.hasText(scopeString)) {
      return Set.of("openid", "profile", "email"); // Default OIDC scopes
    }
    return Arrays.stream(scopeString.split(","))
            .map(String::trim)
            .filter(StringUtils::hasText)
            .collect(Collectors.toSet());
  }
}