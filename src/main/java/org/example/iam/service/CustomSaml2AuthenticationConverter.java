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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * Converts a default {@link Saml2AuthenticationToken} (containing external SAML principal)
 * into a {@link Saml2Authentication} object that uses the locally provisioned {@link User}
 * entity as its principal, effectively integrating the JIT-provisioned user into the
 * Spring Security context.
 * <p>
 * This converter is typically used within the Spring Security SAML configuration
 * ({@link org.example.iam.config.SecurityConfig}) to replace the default conversion logic.
 * </p>
 */
@RequiredArgsConstructor // Inject dependencies via constructor
@Slf4j
// Can be a @Component or defined as a @Bean in SecurityConfig
public class CustomSaml2AuthenticationConverter implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> {

    private final CustomSaml2UserService customSaml2UserService; // Service for JIT provisioning

    /**
     * Performs the conversion from the initial SAML token to the final Authentication object.
     * Handles exceptions during JIT provisioning.
     *
     * @param responseToken The token containing the result from the SAML AuthenticationProvider.
     * @return A Saml2Authentication object with the local User as principal.
     * @throws AuthenticationServiceException If an error occurs during user provisioning lookup/creation.
     */
    @Override
    public Saml2Authentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {

        // Delegate to the default converter to produce a Saml2Authentication instance.
        Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> defaultConverter =
                OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        Saml2Authentication authentication = defaultConverter.convert(responseToken);


        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        String registrationId = responseToken.getToken().getRelyingPartyRegistration().getRegistrationId();
        String samlUsername = principal.getName(); // NameID or equivalent

        log.debug("CustomSaml2AuthenticationConverter processing SAML response for registrationId: {}, SAML Principal Name: {}",
                registrationId, samlUsername);

        try {
            // 1. Use CustomSaml2UserService to find or create the local user based on SAML principal
            User localUser = customSaml2UserService.processSamlUser(principal, registrationId);

            // 2. Extract authorities from the LOCAL user entity
            Collection<? extends GrantedAuthority> authorities = localUser.getAuthorities();
            log.debug("Using authorities from local user '{}': {}", localUser.getUsername(), authorities);

            // 3. Create the final Authentication object.
            Saml2Authentication finalAuthentication = new Saml2Authentication(
                    principal, // Use original SAML principal
                    authentication.getSaml2Response(),
                    authorities // Use authorities derived from our local User
            );
            finalAuthentication.setDetails(localUser);


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