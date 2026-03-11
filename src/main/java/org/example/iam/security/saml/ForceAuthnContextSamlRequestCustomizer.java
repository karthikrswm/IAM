// File: src/main/java/org/example/iam/security/saml/ForceAuthnContextSamlRequestCustomizer.java
package org.example.iam.security.saml;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.*; // OpenSAML core types
// Import the CORRECT nested context class
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.stereotype.Component;

import java.util.function.Consumer;

/**
 * A customizer that modifies the SAML AuthnRequest before it's sent.
 * Implements Consumer for the correct nested AuthnRequestContext type.
 * Adds a RequestedAuthnContext element to request exact context matching.
 */
@Component // Register as a Spring bean
@Slf4j
// Implement Consumer for the correct nested static class AuthnRequestContext
public class ForceAuthnContextSamlRequestCustomizer implements Consumer<OpenSaml4AuthenticationRequestResolver.AuthnRequestContext> {

    @Override
    public void accept(OpenSaml4AuthenticationRequestResolver.AuthnRequestContext context) {
        // The context object passed in is now the correct type

        AuthnRequest authnRequest = context.getAuthnRequest(); // Get OpenSAML AuthnRequest
        String registrationId = context.getRelyingPartyRegistration().getRegistrationId(); // Get RP registration

        log.debug("Applying ForceAuthnContextSamlRequestCustomizer for registrationId: {}", registrationId);

        // Build RequestedAuthnContext element using OpenSAML builders
        try {
            @SuppressWarnings("unchecked")
            SAMLObjectBuilder<RequestedAuthnContext> racBuilder = (SAMLObjectBuilder<RequestedAuthnContext>)
                    XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
            @SuppressWarnings("unchecked")
            SAMLObjectBuilder<AuthnContextClassRef> acrBuilder = (SAMLObjectBuilder<AuthnContextClassRef>)
                    XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

            RequestedAuthnContext requestedAuthnContext = racBuilder.buildObject();
            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

            AuthnContextClassRef passwordProtectedTransportRef = acrBuilder.buildObject();
            passwordProtectedTransportRef.setURI(AuthnContext.PPT_AUTHN_CTX);
            requestedAuthnContext.getAuthnContextClassRefs().add(passwordProtectedTransportRef);

            authnRequest.setRequestedAuthnContext(requestedAuthnContext);
            log.info("Set RequestedAuthnContext with Comparison=EXACT and ClassRef={} for AuthnRequest ID: {}",
                    AuthnContext.PPT_AUTHN_CTX, authnRequest.getID());

        } catch (Exception e) {
            log.error("Failed to build or set RequestedAuthnContext for AuthnRequest ID {} (Registration {}): {}",
                    authnRequest.getID(), registrationId, e.getMessage(), e);
            // Consider re-throwing as a runtime exception to halt processing if critical
            // throw new RuntimeException("Failed to customize AuthnRequest with RequestedAuthnContext", e);
        }
    }
}