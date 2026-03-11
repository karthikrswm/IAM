// File: src/main/java/org/example/iam/service/CustomSaml2AuthenticationConverter.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.entity.User; // The local User entity implementing UserDetails
import org.example.iam.exception.BadRequestException;
import org.example.iam.exception.ConfigurationException;
import org.example.iam.exception.ResourceNotFoundException;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
// Removed Saml2AuthenticationToken import
// import org.springframework.stereotype.Component; // Keep if using component scanning

import java.util.Collection;

/**
 * Converts the SAML Provider's response token into the final Saml2Authentication,
 * performing JIT user provisioning via CustomSaml2UserService.
 * Uses the default converter internally to handle initial conversion steps.
 */
@RequiredArgsConstructor
@Slf4j
// Define as @Bean in SecurityConfig unless using @Component scan for this package
public class CustomSaml2AuthenticationConverter implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> {

    private final CustomSaml2UserService customSaml2UserService; // Service for JIT provisioning

    // Use static instance of default converter provided by Spring Security
    private static final Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> defaultConverter =
            OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();


    @Override
    public Saml2Authentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {

        // *** Use the default converter to get the initial authentication object ***
        Saml2Authentication initialAuthentication = defaultConverter.convert(responseToken);

        if (initialAuthentication == null) {
            log.error("Default SAML response converter returned null authentication object.");
            throw new AuthenticationServiceException("Failed to process initial SAML response.");
        }

        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) initialAuthentication.getPrincipal();
        String registrationId = responseToken.getToken().getRelyingPartyRegistration().getRegistrationId();
        String samlUsername = principal.getName();

        log.debug("CustomSaml2AuthenticationConverter processing SAML response for registrationId: {}, SAML Principal Name: {}",
                registrationId, samlUsername);

        try {
            // Perform JIT provisioning using the dedicated service
            User localUser = customSaml2UserService.processSamlUser(principal, registrationId);

            // Extract authorities from the *local* user entity
            Collection<? extends GrantedAuthority> authorities = localUser.getAuthorities();
            log.debug("Using authorities from local user '{}': {}", localUser.getUsername(), authorities);

            // Create the final Authentication object
            Saml2Authentication finalAuthentication = new Saml2Authentication(
                    principal,
                    initialAuthentication.getSaml2Response(),
                    authorities // <<< Use authorities derived from our local User
            );
            finalAuthentication.setDetails(localUser); // Set local user as details

            log.info("Successfully converted SAML token to final Saml2Authentication for local user '{}' (originally {})",
                    localUser.getUsername(), samlUsername);
            return finalAuthentication;

        } catch (ResourceNotFoundException | BadRequestException | ConfigurationException e) {
            log.error("SAML JIT Provisioning failed for registrationId '{}', SAML principal '{}'. Reason: {}",
                    registrationId, samlUsername, e.getMessage(), e);
            throw new AuthenticationServiceException("SAML User Provisioning Failed: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during SAML JIT user processing/conversion for registrationId '{}', SAML principal '{}': {}",
                    registrationId, samlUsername, e.getMessage(), e);
            throw new AuthenticationServiceException("An unexpected error occurred during SAML user provisioning.", e);
        }
    }
}