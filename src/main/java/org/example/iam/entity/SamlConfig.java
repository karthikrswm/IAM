// File: src/main/java/org/example/iam/entity/SamlConfig.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.iam.audit.Auditable; // Base class for audit fields
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

/**
 * Represents the persisted configuration for a SAML 2.0 Service Provider (SP)
 * specific to an Organization.
 * <p>
 * This entity stores details required for this application (the SP) to interact with
 * an external SAML Identity Provider (IdP) for Single Sign-On (SSO) for users
 * belonging to the associated organization.
 * </p>
 * <p>
 * It extends {@link Auditable} to track creation and modification history.
 * There is a one-to-one relationship with the {@link Organization} entity.
 * </p>
 * <p>
 * **Security Note:** Fields intended to store private keys or full certificates
 * (like {@code serviceProviderSigningCertificate}) should **not** store sensitive material
 * directly in plain text in production. Use a secure vault or encryption mechanism and store
 * only references or encrypted values. These fields currently act as placeholders.
 * </p>
 */
@Entity
@Table(name = "saml_configs", indexes = {
        // Unique constraint ensuring only one SAML config per organization
        @Index(name = "idx_saml_config_org_id", columnList = "organization_id", unique = true),
        // Index on SP entity ID if needed for lookups (e.g., finding config by entity ID)
        @Index(name = "idx_saml_config_sp_entity_id", columnList = "sp_entity_id")
})
@Getter
@Setter
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows copying and modifying using builder pattern
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true) // Include ID and consider Auditable fields
public class SamlConfig extends Auditable<String> { // Audited by String (username/SYSTEM)

  /**
   * Primary key (UUID) for the SAML configuration record.
   */
  @Id
  @GeneratedValue(generator = "UUID")
  @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
  @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
  @EqualsAndHashCode.Include // Use ID for equality checks
  private UUID id;

  /**
   * The Organization to which this SAML configuration applies.
   * Establishes a unique, mandatory one-to-one link. Fetched lazily by default.
   */
  @OneToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "organization_id", nullable = false, unique = true,
          foreignKey = @ForeignKey(name = "fk_saml_config_organization"))
  @ToString.Exclude // Avoid recursion in toString
  private Organization organization;

  /**
   * URL from which the Identity Provider's (IdP) metadata can be dynamically fetched.
   * If provided, often simplifies configuration as many IdP details can be inferred.
   */
  @Column(name = "idp_metadata_url", length = 1024, nullable = true)
  private String identityProviderMetadataUrl;

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
   * Defaults to unspecified.
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
   * Strongly recommended (true) for security.
   */
  @Column(name = "want_assertions_signed", nullable = false)
  @Builder.Default
  private boolean wantAssertionsSigned = true;

  // --- Certificates/Keys (Placeholders - Implement Secure Storage) ---

  /**
   * Placeholder for the Service Provider's signing certificate (public key) in PEM format.
   * Used by the IdP to verify signatures on AuthnRequests if signRequests is true.
   * **WARNING:** Store securely (e.g., in vault), not plain text.
   */
  @Lob
  @Column(name = "sp_signing_certificate", columnDefinition = "TEXT")
  @JdbcTypeCode(SqlTypes.LONGVARCHAR)
  @ToString.Exclude // Exclude potentially large/sensitive data
  private String serviceProviderSigningCertificate; // Placeholder

  /**
   * Placeholder for the Service Provider's decryption key certificate (public key) in PEM format.
   * Used by the IdP to encrypt assertions sent to this SP. Requires corresponding private key for decryption.
   * **WARNING:** Store securely.
   */
  @Lob
  @Column(name = "sp_encryption_certificate", columnDefinition = "TEXT")
  @JdbcTypeCode(SqlTypes.LONGVARCHAR)
  @ToString.Exclude
  private String serviceProviderEncryptionCertificate; // Placeholder

  /**
   * Placeholder for the Identity Provider's signing certificate (public key) in PEM format.
   * Used by this SP to verify the signature on incoming assertions and SLO messages.
   * Often obtained from IdP metadata.
   * **WARNING:** Store securely if not using metadata URL.
   */
  @Lob
  @Column(name = "idp_signing_certificate", columnDefinition = "TEXT")
  @JdbcTypeCode(SqlTypes.LONGVARCHAR)
  @ToString.Exclude
  private String identityProviderSigningCertificate; // Placeholder

  // --- Attribute Mapping ---

  /**
   * Name of the SAML attribute expected to contain the user's primary identifier (username).
   * Defaults to 'uid'.
   */
  @Column(name = "attr_map_username", length = 100, nullable = true)
  @Builder.Default
  private String attributeMappingUsername = "uid";

  /**
   * Name of the SAML attribute expected to contain the user's email address.
   * Defaults to 'mail'.
   */
  @Column(name = "attr_map_email", length = 100, nullable = true)
  @Builder.Default
  private String attributeMappingEmail = "mail";

  /**
   * Name of the SAML attribute expected to contain the user's roles or group memberships. Optional.
   */
  @Column(name = "attr_map_roles", length = 100, nullable = true)
  private String attributeMappingRoles;

  /**
   * Flag indicating whether SAML login is enabled for the organization using this configuration.
   */
  @Column(name = "enabled", nullable = false)
  @Builder.Default
  private boolean enabled = false;

  /**
   * Provides a concise string representation of the SamlConfig, useful for logging.
   * Excludes potentially sensitive certificate/key placeholders and audit details.
   *
   * @return A string representation of the configuration.
   */
  @Override
  public String toString() {
    return "SamlConfig{" +
            "id=" + id +
            ", organizationId=" + (organization != null ? organization.getId() : null) +
            ", serviceProviderEntityId='" + serviceProviderEntityId + '\'' +
            ", enabled=" + enabled +
            ", createdDate=" + createdDate +
            '}';
  }
}