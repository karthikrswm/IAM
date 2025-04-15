// File: src/main/java/org/example/iam/service/CustomOAuth2UserService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.LoginType; // Import LoginType
import org.example.iam.entity.Oauth2Config;
import org.example.iam.entity.Organization;
import org.example.iam.entity.User;
import org.example.iam.exception.BadRequestException; // For user provisioning issues
import org.example.iam.exception.ConfigurationException;
import org.example.iam.exception.ResourceNotFoundException;
import org.example.iam.repository.Oauth2ConfigRepository;
import org.example.iam.repository.OrganizationRepository;
import org.springframework.security.core.GrantedAuthority; // Import GrantedAuthority
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames; // Standard OIDC claim names
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // For find/create user logic
import org.springframework.util.StringUtils;

import java.util.HashSet; // Import HashSet
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Custom implementation of {@link org.springframework.security.oauth2.client.userinfo.OAuth2UserService}
 * designed to handle Just-In-Time (JIT) user provisioning for OAuth 2.0 / OIDC logins.
 * <p>
 * This service overrides the default behavior to:
 * <ol>
 * <li>Fetch user attributes from the external OAuth2 provider.</li>
 * <li>Extract the target {@link Organization} ID from the Spring Security client {@code registrationId}.</li>
 * <li>Validate the Organization's OAuth2 configuration (enabled, correct login type).</li>
 * <li>Extract user identifiers (email, username source) from the provider attributes based on the Organization's configuration.</li>
 * <li>Use the {@link UserService} to find an existing local user matching the email or create a new one (JIT provisioning).</li>
 * <li>Return a {@link DefaultOAuth2User} principal containing attributes from the provider but using authorities (roles)
 * derived from the *local* IAM User entity and using the configured username attribute as the principal's name.</li>
 * </ol>
 * This ensures that users logging in via external OAuth2 providers are seamlessly integrated
 * into the local IAM system with appropriate roles and organization linkage.
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

  // Pattern to extract Org UUID from registrationId (e.g., "google-a1b2c3d4..." or "custom-okta-f0e9d8c7...")
  // Assumes provider prefix, hyphen, then UUID. Adjust if DatabaseClientRegistrationRepository uses a different format.
  private static final Pattern REGISTRATION_ID_ORG_UUID_PATTERN = Pattern.compile("^[a-zA-Z0-9\\-]+-([0-9a-fA-F\\-]{36})$");

  // Dependencies
  private final UserService userService; // For find/create user logic
  private final Oauth2ConfigRepository oauth2ConfigRepository;
  private final OrganizationRepository organizationRepository;

  /**
   * Loads the OAuth2User details, performing JIT provisioning if necessary.
   *
   * @param userRequest The OAuth2 user request containing client registration, access token, etc.
   * @return An {@link OAuth2User} representing the authenticated user (linked to local IAM user).
   * @throws OAuth2AuthenticationException if any error occurs during loading, validation, or provisioning.
   */
  @Override
  @Transactional // Needed for findOrCreateOauth2User which interacts with the DB
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    log.debug("Starting custom OAuth2 user loading process...");

    // 1. Delegate to default implementation to fetch user attributes from provider's UserInfo endpoint
    OAuth2User oauth2User = super.loadUser(userRequest);
    Map<String, Object> attributes = oauth2User.getAttributes();
    log.trace("Fetched attributes from OAuth2 provider: {}", attributes);

    // 2. Extract registrationId and parse the Organization UUID from it
    String registrationId = userRequest.getClientRegistration().getRegistrationId();
    UUID organizationId = extractOrgIdFromRegistrationId(registrationId);
    if (organizationId == null) {
      log.error("Failed to extract Organization UUID from registrationId: '{}'. Format mismatch.", registrationId);
      throw createOAuth2Exception("invalid_registration_id", "Client registration ID format is invalid or missing organization UUID.");
    }
    log.debug("Extracted Organization ID '{}' from registrationId '{}'", organizationId, registrationId);

    // 3. Fetch associated Organization and its OAuth2 Configuration
    Organization organization = organizationRepository.findById(organizationId)
            .orElseThrow(() -> {
              log.error("Organization ID '{}' (from registrationId '{}') not found in database.", organizationId, registrationId);
              return createOAuth2Exception("organization_not_found", "Organization associated with this login configuration was not found.");
            });

    // 4. Validate Organization and Config state
    if (organization.getLoginType() != LoginType.OAUTH2) { // Use LoginType enum
      log.warn("Login attempt via OAuth2 for Org '{}' (ID: {}) which is configured for LoginType: {}.",
              organization.getOrgName(), organizationId, organization.getLoginType());
      throw createOAuth2Exception("login_type_mismatch", "Organization is not configured for OAuth2 login.");
    }

    Oauth2Config oauth2Config = oauth2ConfigRepository.findByOrganization(organization)
            .orElseThrow(() -> {
              log.error("OAuth2 configuration missing for Organization '{}' (ID: {}).", organization.getOrgName(), organizationId);
              return createOAuth2Exception("configuration_error", "OAuth2 configuration missing for the organization.");
            });

    if (!oauth2Config.isEnabled()) {
      log.warn("OAuth2 login attempt for Org '{}' (ID: {}) but the configuration (Provider: {}) is disabled.",
              organization.getOrgName(), organizationId, oauth2Config.getProvider());
      throw createOAuth2Exception("configuration_disabled", "OAuth2 login is currently disabled for this organization.");
    }
    log.debug("Organization '{}' and OAuth2 config (Provider: {}) validated successfully.", organization.getOrgName(), oauth2Config.getProvider());

    // 5. Extract Email and determine Principal Name attribute key based on Org config
    String emailAttributeName = oauth2Config.getUserEmailAttributeName(); // Configured attribute for email
    String userNameAttributeName = oauth2Config.getUserNameAttributeName(); // Configured attribute for principal name

    String email = getAttributeAsString(attributes, emailAttributeName);
    // Default to standard OIDC 'sub' claim if username attribute not configured
    String principalNameAttributeKey = StringUtils.hasText(userNameAttributeName) ? userNameAttributeName : IdTokenClaimNames.SUB;
    String usernameSource = getAttributeAsString(attributes, principalNameAttributeKey); // Get value for the chosen key

    // --- Validation of extracted attributes ---
    if (email == null) {
      log.error("Could not extract required email attribute ('{}') from provider attributes for Org '{}'. Attributes: {}",
              emailAttributeName, organization.getOrgName(), attributes);
      throw createOAuth2Exception("missing_user_email", "Could not retrieve the required email attribute from the identity provider.");
    }
    if (usernameSource == null) {
      log.warn("Could not extract designated username attribute ('{}') for Org '{}'. Using email '{}' as fallback username source.",
              principalNameAttributeKey, organization.getOrgName(), email);
      // Fallback strategy: Use email as the source for username generation in UserService if primary source missing
      usernameSource = email;
      // Note: The principalNameAttributeKey remains what was configured/defaulted, even if the value is missing.
      // Spring Security needs this key to extract the 'name' for the Principal later.
      // If the key itself is absolutely required to exist in attributes, throw an error here instead.
    }
    log.debug("Extracted Email: '{}', Username Source: '{}' (using attribute key '{}')", email, usernameSource, principalNameAttributeKey);

    // 6. Find or Create Local User via UserService (JIT Provisioning)
    try {
      User localUser = userService.findOrCreateOauth2User(
              organization,
              email,
              usernameSource, // Pass the value used for username generation
              registrationId, // Pass context
              attributes      // Pass original attributes for potential use in JIT
      );

      // 7. Construct the final OAuth2User principal for Spring Security
      // Use authorities from the *local* user entity.
      Set<GrantedAuthority> authorities = new HashSet<>(localUser.getAuthorities());

      // The 'name' of the returned principal MUST come from the attribute designated
      // by the 'principalNameAttributeKey'. This key tells Spring Security which attribute
      // in the 'attributes' map holds the value to be used as the principal's name.
      log.info("Successfully processed OAuth2 login for external email '{}'. Mapped to local user '{}' (ID: {}). Returning DefaultOAuth2User.",
              email, localUser.getUsername(), localUser.getId());

      return new DefaultOAuth2User(authorities, attributes, principalNameAttributeKey);

    } catch (ResourceNotFoundException | BadRequestException | ConfigurationException e) {
      // Catch specific exceptions from UserService JIT logic
      log.error("Error during OAuth2 JIT provisioning for external email '{}' (Org: {}): {}", email, organizationId, e.getMessage(), e);
      // Map to OAuth2AuthenticationException
      throw createOAuth2Exception("user_provisioning_error", "Failed to find or create local user account: " + e.getMessage());
    } catch (Exception e) {
      // Catch any other unexpected errors
      log.error("Unexpected error during OAuth2 JIT provisioning for external email '{}' (Org: {}): {}", email, organizationId, e.getMessage(), e);
      throw createOAuth2Exception("internal_error", "An unexpected error occurred during user provisioning.");
    }
  }

  /**
   * Extracts the Organization UUID from the combined registration ID provided by Spring Security.
   * Assumes a format like 'provider-orgUUID' or 'provider_orgUUID'.
   *
   * @param registrationId The registration ID (e.g., "google-a1b2c3d4...").
   * @return The extracted UUID, or {@code null} if the format is invalid or parsing fails.
   */
  private UUID extractOrgIdFromRegistrationId(String registrationId) {
    if (registrationId == null) {
      return null;
    }
    Matcher matcher = REGISTRATION_ID_ORG_UUID_PATTERN.matcher(registrationId);
    if (matcher.matches() && matcher.groupCount() >= 1) {
      try {
        return UUID.fromString(matcher.group(1)); // Group 1 should capture the UUID part
      } catch (IllegalArgumentException e) {
        log.error("Failed to parse UUID from matched group in registrationId '{}'", registrationId, e);
        return null;
      }
    }
    log.warn("RegistrationId '{}' did not match expected pattern for extracting Organization UUID.", registrationId);
    return null;
  }

  /**
   * Safely extracts an attribute value as a String from the provider's attribute map.
   * Handles null attribute names, null map, and null values gracefully.
   *
   * @param attributes    The map of attributes from the OAuth2 provider.
   * @param attributeName The name of the attribute to extract.
   * @return The attribute value as a String, or {@code null} if not found or null.
   */
  private String getAttributeAsString(Map<String, Object> attributes, String attributeName) {
    if (!StringUtils.hasText(attributeName) || attributes == null) {
      return null;
    }
    Object value = attributes.get(attributeName);
    return (value != null) ? value.toString() : null;
  }

  /**
   * Helper method to create an {@link OAuth2AuthenticationException} with a standard error code and description.
   * Logs the error before throwing.
   *
   * @param errorCode   A standard OAuth2 error code (e.g., "invalid_request", "server_error") or a custom one.
   * @param description A human-readable description of the error.
   * @return An OAuth2AuthenticationException instance.
   */
  private OAuth2AuthenticationException createOAuth2Exception(String errorCode, String description) {
    OAuth2Error error = new OAuth2Error(errorCode, description, null); // Error URI is optional
    // Log the specific error clearly before throwing
    log.error("OAuth2 Authentication Error during user loading: Code='{}', Description='{}'", errorCode, description);
    return new OAuth2AuthenticationException(error, error.toString()); // Include error details in exception message
  }
}