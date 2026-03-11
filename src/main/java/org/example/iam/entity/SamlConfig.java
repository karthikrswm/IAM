// File: src/main/java/org/example/iam/entity/SamlConfig.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.iam.audit.Auditable; // Base class for audit fields
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding; // For binding enum
import org.springframework.util.StringUtils; // For toString helper

import java.io.Serial; // Import if using @Serial
import java.io.Serializable; // Import Serializable
import java.util.UUID;

/**
 * Represents the persisted configuration for a SAML 2.0 Service Provider (SP)
 * specific to an Organization.
 * Includes optional fields for manual IdP configuration and separate key alias passwords.
 */
@Entity
@Table(name = "saml_configs", indexes = {
        @Index(name = "idx_saml_config_org_id", columnList = "organization_id", unique = true),
        @Index(name = "idx_saml_config_sp_entity_id", columnList = "sp_entity_id")
})
@Getter
@Setter
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows copying and modifying using builder pattern
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true) // Include ID and consider Auditable fields
public class SamlConfig extends Auditable<String> implements Serializable { // Implement Serializable

  @Serial // Requires Java 14+
  private static final long serialVersionUID = 4L; // Updated version UID

  /**
   * Primary key (UUID) for the SAML configuration record.
   */
  @Id
  @GeneratedValue(strategy = GenerationType.UUID) // Use standard JPA UUID strategy
  @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
  @EqualsAndHashCode.Include // Use ID for equality checks
  private UUID id;

  /**
   * The Organization to which this SAML configuration applies.
   */
  @OneToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "organization_id", nullable = false, unique = true,
          foreignKey = @ForeignKey(name = "fk_saml_config_organization"))
  @ToString.Exclude // Avoid recursion in toString
  private Organization organization;

  /**
   * URL from which the Identity Provider's (IdP) metadata can be dynamically fetched.
   */
  @Column(name = "idp_metadata_url", length = 1024, nullable = true)
  private String identityProviderMetadataUrl;

  // --- SP Details ---
  /**
   * The unique identifier (Entity ID) for this application (Service Provider)
   * as configured in the external IdP for this organization.
   */
  @Column(name = "sp_entity_id", nullable = false, length = 255)
  private String serviceProviderEntityId;

  /**
   * The Assertion Consumer Service (ACS) URL. This is the endpoint in this application
   * where the IdP will send the SAML assertion via the browser.
   */
  @Column(name = "sp_acs_url", nullable = false, length = 1024)
  private String assertionConsumerServiceUrl;

  /**
   * The Single Logout (SLO) Service URL. This is the endpoint in this application
   * where the IdP sends logout requests/responses. Optional.
   */
  @Column(name = "sp_slo_url", length = 1024, nullable = true)
  private String singleLogoutServiceUrl;

  /**
   * The desired format for the NameID in the SAML assertion (e.g., emailAddress, persistent).
   */
  @Column(name = "name_id_format", length = 100, nullable = true)
  @Builder.Default
  private String nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

  /**
   * Flag indicating whether SAML authentication requests (AuthnRequests) sent from this SP
   * to the IdP should be digitally signed. Requires SP signing credentials.
   */
  @Column(name = "sign_requests", nullable = false)
  @Builder.Default
  private boolean signRequests = false;

  /**
   * Flag indicating whether incoming SAML assertions from the IdP *must* be signed.
   */
  @Column(name = "want_assertions_signed", nullable = false)
  @Builder.Default
  private boolean wantAssertionsSigned = true;

  // --- Manual IdP Configuration Fields (Fallback) ---
  /**
   * Manual configuration for IdP Entity ID. Used if metadata URL is missing/fails.
   */
  @Column(name = "idp_entity_id", length = 255, nullable = true)
  private String identityProviderEntityId;

  /**
   * Manual configuration for the IdP's Single Sign-On service URL. Used if metadata URL is missing/fails.
   */
  @Column(name = "idp_sso_url", length = 1024, nullable = true)
  private String singleSignOnServiceUrl;

  /**
   * Manual configuration for the SAML binding the IdP uses for SSO. Used if metadata URL is missing/fails.
   */
  @Enumerated(EnumType.STRING)
  @Column(name = "idp_sso_binding", length = 10, nullable = true) // POST or REDIRECT
  private Saml2MessageBinding singleSignOnServiceBinding;

  // --- SP Signing Credentials ---
  /**
   * Path/reference to the keystore containing the SP signing key/cert.
   */
  @Column(name = "sp_signing_keystore_path", length = 255, nullable = true)
  @ToString.Exclude
  private String spSigningKeystorePath;

  /**
   * ENCRYPTED password for the SP signing keystore file.
   */
  @Column(name = "sp_signing_keystore_password_encrypted", length = 512, nullable = true)
  @ToString.Exclude
  private String spSigningKeystorePasswordEncrypted; // Keystore password

  /**
   * Alias of the signing key/cert entry within the SP signing keystore.
   */
  @Column(name = "sp_signing_key_alias", length = 100, nullable = true)
  @ToString.Exclude
  private String spSigningKeyAlias;

  /**
   * ENCRYPTED password specifically for the signing private key alias within the keystore.
   * If null, the keystore password is assumed to apply to the key as well.
   */
  @Column(name = "sp_signing_key_password_encrypted", length = 512, nullable = true) // <<< ADDED
  @ToString.Exclude
  private String spSigningKeyPasswordEncrypted;

  // --- SP Encryption Credentials ---
  /**
   * Path/reference to the keystore containing the SP encryption key/cert.
   */
  @Column(name = "sp_encryption_keystore_path", length = 255, nullable = true)
  @ToString.Exclude
  private String spEncryptionKeystorePath;

  /**
   * ENCRYPTED password for the SP encryption keystore file.
   */
  @Column(name = "sp_encryption_keystore_password_encrypted", length = 512, nullable = true)
  @ToString.Exclude
  private String spEncryptionKeystorePasswordEncrypted; // Keystore password

  /**
   * Alias of the encryption key/cert entry within the SP encryption keystore.
   */
  @Column(name = "sp_encryption_key_alias", length = 100, nullable = true)
  @ToString.Exclude
  private String spEncryptionKeyAlias;

  /**
   * ENCRYPTED password specifically for the encryption private key alias within the keystore.
   * If null, the keystore password is assumed to apply to the key as well.
   */
  @Column(name = "sp_encryption_key_password_encrypted", length = 512, nullable = true) // <<< ADDED
  @ToString.Exclude
  private String spEncryptionKeyPasswordEncrypted;

  // --- IdP Verification Certificate ---
  /**
   * Optional: Explicitly store the IdP's verification certificate in PEM format.
   * Can override or supplement certificate(s) found in metadata.
   */
  @Lob
  @Column(name = "idp_verification_certificate_pem", columnDefinition = "TEXT")
  @JdbcTypeCode(SqlTypes.LONGVARCHAR)
  @ToString.Exclude
  private String idpVerificationCertificatePem;

  // --- Attribute Mapping ---
  /**
   * Name of the SAML attribute for username mapping. Defaults to 'uid'.
   */
  @Column(name = "attr_map_username", length = 100, nullable = true)
  @Builder.Default
  private String attributeMappingUsername = "uid";

  /**
   * Name of the SAML attribute for email mapping. Defaults to 'mail'.
   */
  @Column(name = "attr_map_email", length = 100, nullable = true)
  @Builder.Default
  private String attributeMappingEmail = "mail";

  /**
   * Name of the SAML attribute for roles/groups mapping. Optional.
   */
  @Column(name = "attr_map_roles", length = 100, nullable = true)
  private String attributeMappingRoles;

  /**
   * Flag indicating whether SAML login is enabled for the organization.
   */
  @Column(name = "enabled", nullable = false)
  @Builder.Default
  private boolean enabled = false;


  /**
   * Provides a concise string representation of the SamlConfig.
   */
  @Override
  public String toString() {
    return "SamlConfig{" +
            "id=" + id +
            ", organizationId=" + (organization != null ? organization.getId() : null) +
            ", serviceProviderEntityId='" + serviceProviderEntityId + '\'' +
            ", signingKeystoreConfigured=" + (StringUtils.hasText(spSigningKeystorePath) && StringUtils.hasText(spSigningKeyAlias)) +
            ", encryptionKeystoreConfigured=" + (StringUtils.hasText(spEncryptionKeystorePath) && StringUtils.hasText(spEncryptionKeyAlias)) +
            ", enabled=" + enabled +
            ", createdDate=" + createdDate +
            '}';
  }
}