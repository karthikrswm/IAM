// File: src/main/java/org/example/iam/repository/DatabaseClientRegistrationRepository.java
package org.example.iam.repository;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.entity.Oauth2Config;
import org.example.iam.entity.Organization; // Import Organization for Org Name logging
import org.example.iam.exception.ConfigurationException; // Import exception
// Import EncryptionService if used for client secrets
// import org.example.iam.service.EncryptionService;
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
 * **Security Note:** Handling of client secrets requires careful implementation. The current
 * placeholder assumes secrets are stored (insecurely) in the Oauth2Config entity. Production systems
 * MUST use a secure mechanism like an external vault or robust encryption/decryption service
 * (e.g., injecting an {@code EncryptionService}).
 * </p>
 */
@Repository("databaseClientRegistrationRepository") // Explicit bean name for clarity/injection
@RequiredArgsConstructor
@Slf4j
public class DatabaseClientRegistrationRepository implements ClientRegistrationRepository,
        Iterable<ClientRegistration> { // Implement Iterable for discovery

  private final Oauth2ConfigRepository oauth2ConfigRepository;
  // Uncomment and inject if using an encryption service for secrets
  // private final EncryptionService encryptionService;

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
    // In a real application, ensure Oauth2ConfigRepository has a findByEnabledTrue() method
    // or filter the results here. For simplicity, loading all and filtering.
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
        // Log critical failure for a specific config but continue loading others
        log.error("!!! Failed to build OAuth2 client registration for DB config ID {}. OrgID: {}. Error: {} !!!",
                config.getId(),
                config.getOrganization() != null ? config.getOrganization().getId() : "N/A",
                e.getMessage(), e);
        // Depending on policy, might want to throw exception here to halt startup if any config fails
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
   * from the application's {@link Oauth2Config} entity.
   *
   * @param config The {@link Oauth2Config} entity from the database.
   * @return A configured {@link ClientRegistration} object, or null if construction fails.
   * @throws ConfigurationException if essential configuration is missing or invalid.
   */
  private ClientRegistration buildClientRegistration(Oauth2Config config) {
    log.debug("Building ClientRegistration for Oauth2Config ID: {}", config.getId());

    // Ensure organization link exists (should be caught by filter in loadClientRegistrations, but double-check)
    if (config.getOrganization() == null) {
      log.error("Cannot build ClientRegistration: Oauth2Config ID {} is not linked to an Organization.", config.getId());
      return null; // Or throw ConfigurationException
    }
    Organization org = config.getOrganization();

    // 1. Generate the unique registrationId for Spring Security
    String registrationId = generateRegistrationId(config.getProvider(), org.getId());

    // 2. Handle Client Secret (Placeholder for secure retrieval/decryption)
    String clientSecret = config.getClientSecret(); // *** INSECURE PLACEHOLDER ***
    // --- Example Secure Handling ---
    // if (encryptionService != null && StringUtils.hasText(config.getEncryptedClientSecret())) {
    //     try {
    //         clientSecret = encryptionService.decrypt(config.getEncryptedClientSecret());
    //     } catch (Exception e) {
    //         log.error("FATAL: Failed to decrypt client secret for OAuth2 config ID {}. Registration cannot be built.", config.getId(), e);
    //         throw new ConfigurationException("Failed to decrypt client secret for OAuth2 config " + config.getId(), e);
    //     }
    // } else
    if (!StringUtils.hasText(clientSecret)) {
      log.error("FATAL: Client secret is missing for OAuth2 config ID {}. Registration cannot be built.", config.getId());
      throw new ConfigurationException("Client secret is required for OAuth2 config " + config.getId());
    }

    // 3. Use ClientRegistration builder
    ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
            .clientId(config.getClientId())
            .clientSecret(clientSecret) // Use the potentially decrypted secret
            // Common settings - can be made configurable in Oauth2Config if needed
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            // The redirect URI template Spring Security will use - must match provider config
            .redirectUri(StringUtils.hasText(config.getRedirectUriTemplate())
                    ? config.getRedirectUriTemplate()
                    : "{baseUrl}/login/oauth2/code/{registrationId}") // Default pattern
            // Provider details - URIs might be auto-discovered for common providers by Spring Boot,
            // but providing them from DB ensures consistency, especially for custom providers.
            .authorizationUri(config.getAuthorizationUri())
            .tokenUri(config.getTokenUri())
            .userInfoUri(config.getUserInfoUri())
            .jwkSetUri(config.getJwkSetUri())
            // Parse scopes from comma-separated string in DB config
            .scope(parseScopes(config.getScopes()))
            // Attribute name used to extract the principal's name (subject)
            .userNameAttributeName(StringUtils.hasText(config.getUserNameAttributeName())
                    ? config.getUserNameAttributeName()
                    : IdTokenClaimNames.SUB) // Default to 'sub' for OIDC
            // Client name displayed to the user (optional but good practice)
            .clientName(config.getProvider() + " (" + org.getOrgName() + ")"); // e.g., "Google (Example Corp)"


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