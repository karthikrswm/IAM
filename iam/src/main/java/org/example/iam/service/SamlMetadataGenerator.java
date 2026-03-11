// File: src/main/java/org/example/iam/service/SamlMetadataGenerator.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Collection;

/**
 * Service responsible for generating SAML 2.0 Service Provider metadata XML
 * based on the application's configuration for a specific organization.
 * Uses standard Java XML streaming API for generation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SamlMetadataGenerator {

    // XML Namespace constants
    private static final String NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String NS_DS = "http://www.w3.org/2000/09/xmldsig#";

    /**
     * Generates the SAML 2.0 SP Metadata XML based on a RelyingPartyRegistration object.
     *
     * @param registration The RelyingPartyRegistration containing SP configuration details.
     * @return A String containing the generated SAML metadata XML.
     * @throws RuntimeException wrapping underlying XML or Certificate exceptions if generation fails.
     */
    public String generateMetadataXml(RelyingPartyRegistration registration) {
        if (registration == null) {
            log.error("Cannot generate metadata: RelyingPartyRegistration is null.");
            throw new IllegalArgumentException("RelyingPartyRegistration cannot be null for metadata generation.");
        }

        log.info("Generating SAML SP metadata for registrationId: {}", registration.getRegistrationId());
        XMLStreamWriter writer = null;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            XMLOutputFactory factory = XMLOutputFactory.newInstance();
            // factory.setProperty(XMLOutputFactory.SUPPORT_DTD, false); // REMOVED - Not standard
            factory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, true);

            writer = factory.createXMLStreamWriter(baos, StandardCharsets.UTF_8.name());

            writer.writeStartDocument(StandardCharsets.UTF_8.name(), "1.0");
            writer.writeStartElement("md", "EntityDescriptor", NS_MD);
            writer.writeNamespace("md", NS_MD);
            writer.writeNamespace("ds", NS_DS);
            writer.writeAttribute("entityID", registration.getEntityId());

            writer.writeStartElement(NS_MD, "SPSSODescriptor");
            writer.writeAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
            writer.writeAttribute("AuthnRequestsSigned", String.valueOf(registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()));
            // Removed WantAssertionsSigned attribute

            // Key Descriptors
            appendKeyDescriptors(writer, registration.getSigningX509Credentials(), "signing");
            appendKeyDescriptors(writer, registration.getDecryptionX509Credentials(), "encryption");

            // Single Logout Service Endpoint(s)
            if (StringUtils.hasText(registration.getSingleLogoutServiceLocation())) {
                appendSloService(writer, registration.getSingleLogoutServiceLocation(), registration.getSingleLogoutServiceBinding());
                String sloResponseLocation = StringUtils.hasText(registration.getSingleLogoutServiceResponseLocation()) ?
                        registration.getSingleLogoutServiceResponseLocation() : registration.getSingleLogoutServiceLocation();
                if(!registration.getSingleLogoutServiceLocation().equals(sloResponseLocation)) {
                    appendSloService(writer, sloResponseLocation, registration.getSingleLogoutServiceBinding());
                }
            }

            // NameID Formats supported/preferred by SP
            appendNameIdFormat(writer, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            appendNameIdFormat(writer, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
            appendNameIdFormat(writer, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

            // Assertion Consumer Service (ACS) Endpoint
            writer.writeStartElement(NS_MD, "AssertionConsumerService");
            writer.writeAttribute("Binding", registration.getAssertionConsumerServiceBinding().getUrn());
            writer.writeAttribute("Location", registration.getAssertionConsumerServiceLocation());
            writer.writeAttribute("index", "0");
            writer.writeAttribute("isDefault", "true");
            writer.writeEndElement(); // AssertionConsumerService

            writer.writeEndElement(); // SPSSODescriptor
            writer.writeEndElement(); // EntityDescriptor
            writer.writeEndDocument();

            writer.flush();
            String xml = baos.toString(StandardCharsets.UTF_8);
            log.info("Successfully generated SAML SP metadata XML for entityID: {}", registration.getEntityId());
            return xml;

        } catch (XMLStreamException | IOException e) {
            log.error("Failed to generate SAML SP metadata XML for registrationId {}: {}",
                    registration.getRegistrationId(), e.getMessage(), e);
            throw new RuntimeException("Failed to generate SAML Service Provider metadata", e);
        } finally {
            if (writer != null) {
                try { writer.close(); } catch (XMLStreamException e) { log.warn("Error closing XMLStreamWriter", e); }
            }
        }
    }

    /** Helper to append KeyDescriptor elements based on configured credentials */
    private void appendKeyDescriptors(XMLStreamWriter writer, Collection<Saml2X509Credential> credentials, String use) throws XMLStreamException {
        if (credentials == null || credentials.isEmpty()) return;
        for (Saml2X509Credential credential : credentials) {
            if (credential.getCertificate() != null) {
                writer.writeStartElement("md", "KeyDescriptor", NS_MD);
                if (StringUtils.hasText(use)) {
                    writer.writeAttribute("use", use);
                }
                writer.writeStartElement("ds", "KeyInfo", NS_DS);
                writer.writeStartElement("ds", "X509Data", NS_DS);
                writer.writeStartElement("ds", "X509Certificate", NS_DS);
                try {
                    String certBase64 = Base64.getEncoder().encodeToString(credential.getCertificate().getEncoded());
                    writer.writeCharacters(certBase64);
                } catch (CertificateEncodingException e) {
                    log.error("Failed to encode certificate for metadata (use={}): {}", use, e.getMessage());
                    throw new RuntimeException("Failed to encode certificate for metadata", e);
                }
                writer.writeEndElement(); // X509Certificate
                writer.writeEndElement(); // X509Data
                writer.writeEndElement(); // KeyInfo
                writer.writeEndElement(); // KeyDescriptor
            }
        }
    }

    /** Helper to append SingleLogoutService elements */
    private void appendSloService(XMLStreamWriter writer, String location, Saml2MessageBinding binding) throws XMLStreamException {
        writer.writeStartElement("md", "SingleLogoutService", NS_MD);
        writer.writeAttribute("Binding", binding.getUrn());
        writer.writeAttribute("Location", location);
        writer.writeEndElement(); // SingleLogoutService
    }

    /** Helper to append NameIDFormat elements */
    private void appendNameIdFormat(XMLStreamWriter writer, String format) throws XMLStreamException {
        writer.writeStartElement("md", "NameIDFormat", NS_MD);
        writer.writeCharacters(format);
        writer.writeEndElement(); // NameIDFormat
    }
}