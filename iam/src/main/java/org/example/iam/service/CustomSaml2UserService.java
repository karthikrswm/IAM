// File: src/main/java/org/example/iam/service/CustomSaml2UserService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages; // Added import
import org.example.iam.constant.LoginType; // Import LoginType
import org.example.iam.entity.Organization;
import org.example.iam.entity.SamlConfig;
import org.example.iam.entity.User;
import org.example.iam.exception.BadRequestException;
import org.example.iam.exception.ConfigurationException;
import org.example.iam.exception.ResourceNotFoundException;
import org.example.iam.repository.OrganizationRepository;
import org.example.iam.repository.SamlConfigRepository;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
// Import Saml2Authentication if needed for full context processing
// import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // For find/create user logic
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service responsible for handling SAML 2.0 Just-In-Time (JIT) user provisioning.
 * <p>
 * **Integration Point:** This service is intended to be called *after* successful SAML
 * authentication validation but *before* the final Spring Security {@code Authentication}
 * object is fully established. The exact integration point depends on the chosen customization
 * strategy within Spring Security's SAML framework, common options include:
 * <ul>
 * <li>A custom {@code Converter<Saml2Authentication, ? extends AbstractAuthenticationToken>}.</li>
 * <li>A custom {@code AuthenticationProvider} that decorates or replaces the default one.</li>
 * <li>A custom {@code Saml2AuthenticationSuccessHandler}.</li>
 * </ul>
 * </p>
 * <p>
 * **Functionality:**
 * <ol>
 * <li>Receives the authenticated {@link Saml2AuthenticatedPrincipal} containing assertion attributes.</li>
 * <li>Extracts the target {@link Organization} ID from the {@code registrationId}.</li>
 * <li>Validates the Organization's SAML configuration (enabled, correct login type).</li>
 * <li>Extracts user identifiers (email, username source) from the SAML attributes based on the Organization's configuration.</li>
 * <li>Uses the {@link UserService} to find an existing local user matching the email or create a new one (JIT provisioning).</li>
 * <li>Returns the *local* {@link User} entity. The calling component is then responsible for using this local user
 * (especially its authorities) to construct the final {@code Saml2Authentication} object placed in the SecurityContext.</li>
 * </ol>
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomSaml2UserService {

  // Pattern to extract Org UUID from registrationId (e.g., "saml-org-UUID")
  // Ensure this matches the pattern used in DatabaseRelyingPartyRegistrationRepository
  private static final Pattern REGISTRATION_ID_ORG_UUID_PATTERN = Pattern.compile("^[a-zA-Z0-9\\-]+-([0-9a-fA-F\\-]{36})$");

  // Dependencies
  private final UserService userService; // To find/create local user
  private final OrganizationRepository organizationRepository;
  private final SamlConfigRepository samlConfigRepository;

  /**
   * Processes the authenticated SAML principal and assertion attributes to perform
   * Just-In-Time (JIT) user provisioning. Finds or creates a local IAM user corresponding
   * to the external SAML identity.
   *
   * @param principal      The authenticated principal derived from the SAML assertion,
   * containing attributes and the NameID.
   * @param registrationId The registration ID identifying the Relying Party (SP) configuration
   * used for this authentication flow (e.g., "saml-org-UUID").
   * @return The corresponding local {@link User} entity (found or newly created).
   * @throws ResourceNotFoundException if the organization or its SAML config is not found.
   * @throws ConfigurationException    if essential configuration (like attribute mapping) is missing or invalid,
   * or if the organization is not configured for SAML.
   * @throws BadRequestException       if required attributes are missing from the assertion, email domain validation fails,
   * or user creation fails due to conflicts (handled by UserService).
   */
  @Transactional // Database operations (find/create user) require a transaction
  public User processSamlUser(Saml2AuthenticatedPrincipal principal, String registrationId) {
    log.debug("Starting custom SAML user processing for registrationId: {}", registrationId);

    // 1. Extract Organization ID from registrationId
    UUID organizationId = extractOrgIdFromRegistrationId(registrationId);
    if (organizationId == null) {
      log.error("Could not extract Organization ID from SAML registrationId '{}'. Cannot provision user.", registrationId);
      // Throw an exception that the calling authentication component can handle
      throw new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (Invalid SAML registration ID format: " + registrationId + ")"); // Use constant
    }
    log.debug("Extracted Organization ID '{}' from registrationId '{}'", organizationId, registrationId);


    // 2. Fetch associated Organization and its SAML Configuration
    Organization organization = organizationRepository.findById(organizationId)
            .orElseThrow(() -> {
              String orgNotFoundMsg = String.format(ApiErrorMessages.ORGANIZATION_NOT_FOUND_ID, organizationId); // Use constant
              log.error(orgNotFoundMsg + " for SAML registrationId '{}'.", registrationId);
              return new ResourceNotFoundException(orgNotFoundMsg); // Use constant message
            });

    // 3. Validate Organization and Config state
    if (organization.getLoginType() != LoginType.SAML) { // Use LoginType enum
      log.error("Organization '{}' (ID: {}) is not configured for SAML login (Type: {}). RegistrationId: {}",
              organization.getOrgName(), organizationId, organization.getLoginType(), registrationId);
      throw new ConfigurationException(ApiErrorMessages.OPERATION_NOT_ALLOWED + " (Organization not configured for SAML login)"); // Use constant
    }

    SamlConfig samlConfig = samlConfigRepository.findByOrganization(organization)
            .orElseThrow(() -> {
              String configMissingMsg = "SAML configuration missing for organization '" + organization.getOrgName() + "'.";
              log.error(configMissingMsg + " (ID: {}). RegistrationId: {}",
                      organizationId, registrationId);
              return new ConfigurationException(ApiErrorMessages.CONFIGURATION_ERROR + " (" + configMissingMsg + ")"); // Use constant
            });

    if (!samlConfig.isEnabled()) {
      log.warn("SAML login attempt for Org '{}' (ID: {}) but the configuration is disabled. RegistrationId: {}",
              organization.getOrgName(), organizationId, registrationId);
      throw new ConfigurationException(ApiErrorMessages.OPERATION_NOT_ALLOWED + " (SAML login is disabled for this organization)"); // Use constant
    }
    log.debug("Organization '{}' and SAML config validated successfully.", organization.getOrgName());

    // 4. Extract required attributes based on SAML config mapping
    Map<String, List<Object>> attributes = principal.getAttributes(); // Attributes from SAML Assertion
    log.trace("Received SAML attributes: {}", attributes);

    String emailAttributeName = samlConfig.getAttributeMappingEmail();
    String usernameAttributeName = samlConfig.getAttributeMappingUsername(); // May map to NameID or other attr

    // NameID is often the primary identifier in SAML, available via principal.getName()
    String nameId = principal.getName();
    String email = getFirstAttributeValue(attributes, emailAttributeName);
    // Get the value from the attribute configured to represent the username source
    String usernameSource = getFirstAttributeValue(attributes, usernameAttributeName);

    // --- Fallback strategy for username source ---
    if (usernameSource == null) {
      // If the configured attribute isn't present, decide on a fallback: NameID or Email?
      // Using NameID might be more common in SAML contexts if available.
      if (StringUtils.hasText(nameId)) {
        usernameSource = nameId;
        log.warn("SAML username attribute ('{}') not found for registrationId '{}'. Using NameID ('{}') as username source.",
                usernameAttributeName, registrationId, nameId);
      } else {
        // If NameID is also missing/blank, fall back to email prefix (less ideal but possible)
        usernameSource = email; // Email must exist at this point due to validation below
        log.warn("SAML username attribute ('{}') and NameID not found/blank for registrationId '{}'. Using email ('{}') as username source.",
                usernameAttributeName, registrationId, email);
      }
    }

    // --- Validation of extracted attributes ---
    if (email == null) {
      String missingEmailMsg = "Could not retrieve the required email attribute ('" + emailAttributeName + "') from the SAML assertion.";
      log.error(missingEmailMsg + " for Org '{}'. NameID: '{}', Attributes: {}",
              organization.getOrgName(), nameId, attributes);
      throw new BadRequestException(ApiErrorMessages.INVALID_INPUT + " (" + missingEmailMsg + ")"); // Use constant
    }
    if (usernameSource == null) {
      // This should only happen if email was also null, which is caught above.
      String missingUserSourceMsg = "Unable to determine a user identifier from the SAML assertion (checked NameID, attribute '" + usernameAttributeName + "', and email)";
      log.error(missingUserSourceMsg + " for Org '{}'.", organization.getOrgName());
      throw new BadRequestException(ApiErrorMessages.INVALID_INPUT + " (" + missingUserSourceMsg + ")"); // Use constant
    }
    log.debug("Extracted Email: '{}', Username Source: '{}' (from NameID/Attribute '{}')", email, usernameSource, usernameAttributeName != null ? usernameAttributeName : "NameID/Email Fallback");


    // 5. Delegate to UserService to find or create the local IAM user
    try {
      // Pass extracted details to the user service for JIT logic
      User localUser = userService.findOrCreateSamlUser(
              organization,
              email,
              usernameSource, // Source identifier for username generation
              registrationId, // Contextual info
              attributes      // Pass original attributes for potential use
      );

      log.info("Successfully processed SAML login for external email '{}'. Mapped to local user '{}' (ID: {}).",
              email, localUser.getUsername(), localUser.getId());

      // Return the local User entity.
      // The calling component (e.g., custom AuthenticationProvider/Converter) must use this
      // User's details (especially authorities) to build the final Saml2Authentication object.
      return localUser;

    } catch (ResourceNotFoundException | BadRequestException | ConfigurationException e) {
      // Catch specific exceptions from UserService JIT logic
      log.error("Error during SAML JIT provisioning for external email '{}' (Org: {}): {}", email, organizationId, e.getMessage(), e);
      // Re-throw the exception for the calling authentication component to handle
      throw e;
    } catch (Exception e) {
      // Catch any other unexpected errors
      log.error("Unexpected error during SAML JIT provisioning for external email '{}' (Org: {}): {}", email, organizationId, e.getMessage(), e);
      // Wrap in a ConfigurationException or a SAML-specific exception if available/appropriate
      throw new ConfigurationException(ApiErrorMessages.GENERAL_ERROR + " (SAML user provisioning)", e); // Use constant
    }
  }

  /**
   * Extracts the Organization UUID from the combined registration ID provided by Spring Security.
   * Assumes a format like 'prefix-orgUUID'.
   *
   * @param registrationId The registration ID (e.g., "saml-org-a1b2c3d4...").
   * @return The extracted UUID, or {@code null} if the format is invalid or parsing fails.
   */
  private UUID extractOrgIdFromRegistrationId(String registrationId) {
    if (registrationId == null) {
      return null;
    }
    Matcher matcher = REGISTRATION_ID_ORG_UUID_PATTERN.matcher(registrationId);
    if (matcher.matches() && matcher.groupCount() >= 1) {
      try {
        return UUID.fromString(matcher.group(1)); // Group 1 captures the UUID
      } catch (IllegalArgumentException e) {
        log.error("Failed to parse UUID from matched group in registrationId '{}'", registrationId, e);
        return null;
      }
    }
    log.warn("SAML RegistrationId '{}' did not match expected pattern for extracting Organization UUID.", registrationId);
    return null;
  }

  /**
   * Safely extracts the first value of a potentially multi-valued SAML attribute as a String.
   * Handles null attribute name, null map, empty list, and null values gracefully.
   *
   * @param attributes    Map of attributes from the SAML assertion (Key: attribute name, Value: List of objects).
   * @param attributeName The friendly name or URI of the SAML attribute to extract.
   * @return The first attribute value as a String, or {@code null} if not found or null/empty.
   */
  private String getFirstAttributeValue(Map<String, List<Object>> attributes, String attributeName) {
    if (!StringUtils.hasText(attributeName) || attributes == null) {
      return null;
    }
    List<Object> values = attributes.get(attributeName);
    if (values == null || values.isEmpty() || values.get(0) == null) {
      // Log if expected attribute is missing or empty? Maybe at DEBUG level.
      // log.debug("Attribute '{}' not found or is empty/null in SAML assertion.", attributeName);
      return null;
    }
    // Return the first value converted to String
    return values.get(0).toString();
  }
}