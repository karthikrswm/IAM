// File: src/main/java/org/example/iam/entity/Organization.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.iam.audit.Auditable; // Base class for audit fields
import org.example.iam.constant.LoginType;
import org.hibernate.annotations.GenericGenerator;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects; // Import Objects for null-safe equals
import java.util.Set;
import java.util.UUID;

/**
 * Represents an Organization (Tenant) within the IAM system.
 * <p>
 * Each organization acts as a boundary for users, configurations (like SSO), and potentially
 * other resources. It defines key properties like its name, domain, and the required login
 * mechanism for its users.
 * </p>
 * <p>
 * It extends {@link Auditable} to track creation and modification history.
 * Includes relationships to {@link User}, {@link SamlConfig}, and {@link Oauth2Config}.
 * </p>
 */
@Entity
@Table(name = "organizations", uniqueConstraints = {
        // Ensure organization names and domains are unique across the system
        @UniqueConstraint(columnNames = "org_name", name = "uk_org_name"),
        @UniqueConstraint(columnNames = "org_domain", name = "uk_org_domain")
})
@Getter // Lombok: Generate getters
@Setter // Lombok: Generate setters
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows copying and modifying using builder pattern
// Include ID for equality checks, call super for Auditable fields' equality
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true)
public class Organization extends Auditable<String> implements Serializable { // Audited by String (username/SYSTEM)

  @Serial // Requires Java 14+
  private static final long serialVersionUID = 3L; // Basic version UID
  /**
   * Primary key (UUID) for the organization.
   */
  @Id
  @GeneratedValue(generator = "UUID")
  @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
  @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
  @EqualsAndHashCode.Include // Use ID for equality checks
  private UUID id;

  /**
   * The unique name of the organization.
   */
  @Column(name = "org_name", nullable = false, unique = true, length = 100)
  private String orgName;

  /**
   * The unique primary internet domain associated with the organization (e.g., "example.com").
   * Used for user email validation and potential SSO configurations.
   */
  @Column(name = "org_domain", nullable = false, unique = true, length = 100)
  private String orgDomain;

  /**
   * The required login mechanism (JWT, SAML, OAUTH2) for regular users of this organization.
   * Stored as a string representation of the {@link LoginType} enum.
   */
  @Enumerated(EnumType.STRING)
  @Column(name = "login_type", nullable = false, length = 10) // Length matches enum names
  private LoginType loginType;

  /**
   * Flag indicating if this is the special "Super Organization" used for system administration.
   * There should typically be only one Super Organization.
   */
  @Column(name = "is_super_org", nullable = false)
  @Builder.Default // Default new orgs to NOT be super orgs
  private boolean isSuperOrg = false;

  // --- Relationships ---

  /**
   * Set of users belonging to this organization.
   * One-to-Many relationship: One Organization has Many Users.
   * - `mappedBy = "organization"`: Indicates the `organization` field in the `User` entity owns the relationship.
   * - `cascade = CascadeType.ALL`: Operations (persist, merge, remove) on Organization cascade to its Users.
   * - `orphanRemoval = true`: If a User is removed from this Set, it will be deleted from the database.
   * - `Workspace = FetchType.LAZY`: Users are not loaded automatically when the Organization is fetched.
   */
  @OneToMany(mappedBy = "organization", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
  @ToString.Exclude // Exclude from toString to avoid recursion and potentially large output
  @Builder.Default // Initialize the set using the builder's default
  private Set<User> users = new HashSet<>();

  /**
   * The SAML 2.0 configuration associated with this organization (if any).
   * One-to-One relationship: One Organization has One SamlConfig.
   * - `mappedBy = "organization"`: The `organization` field in `SamlConfig` owns the relationship.
   * - `cascade = CascadeType.ALL`, `orphanRemoval = true`: SamlConfig lifecycle is tied to the Organization.
   * - `Workspace = FetchType.LAZY`: Config is loaded only when explicitly accessed.
   */
  @OneToOne(mappedBy = "organization", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
  @ToString.Exclude // Exclude from toString
  private SamlConfig samlConfig;

  /**
   * The OAuth 2.0 configuration associated with this organization (if any).
   * One-to-One relationship: One Organization has One Oauth2Config.
   * Configuration details are similar to `samlConfig`.
   */
  @OneToOne(mappedBy = "organization", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
  @ToString.Exclude // Exclude from toString
  private Oauth2Config oauth2Config;

  // --- Convenience Methods for Relationship Management ---

  /**
   * Adds a user to this organization, setting the bidirectional relationship.
   *
   * @param user The User entity to add. Should not be null.
   */
  public void addUser(User user) {
    if (user != null && this.users.add(user)) { // Ensure user is not null and successfully added to set
      user.setOrganization(this); // Set the back-reference on the user side
    }
  }

  /**
   * Removes a user from this organization, clearing the bidirectional relationship.
   * Note: Due to `orphanRemoval = true`, removing the user from the collection
   * will trigger its deletion from the database when the Organization is persisted/merged.
   *
   * @param user The User entity to remove. Should not be null.
   */
  public void removeUser(User user) {
    if (user != null && this.users.remove(user)) { // Ensure user is not null and successfully removed from set
      user.setOrganization(null); // Clear the back-reference on the user side
    }
  }

  /**
   * Sets the SAML configuration for this organization, managing the bidirectional link.
   * If a new config is provided, it links it to this organization.
   * If null is provided, it clears the link from any existing config.
   *
   * @param newSamlConfig The new SamlConfig entity, or null to remove the association.
   */
  public void setSamlConfig(SamlConfig newSamlConfig) {
    if (!Objects.equals(this.samlConfig, newSamlConfig)) {
      // Break link with old config if it exists
      if (this.samlConfig != null) {
        this.samlConfig.setOrganization(null);
      }
      this.samlConfig = newSamlConfig;
      // Set link with new config if it exists
      if (newSamlConfig != null) {
        newSamlConfig.setOrganization(this);
      }
    }
  }

  /**
   * Sets the OAuth2 configuration for this organization, managing the bidirectional link.
   * Logic is similar to {@link #setSamlConfig(SamlConfig)}.
   *
   * @param newOauth2Config The new Oauth2Config entity, or null to remove the association.
   */
  public void setOauth2Config(Oauth2Config newOauth2Config) {
    if (!Objects.equals(this.oauth2Config, newOauth2Config)) {
      // Break link with old config
      if (this.oauth2Config != null) {
        this.oauth2Config.setOrganization(null);
      }
      this.oauth2Config = newOauth2Config;
      // Set link with new config
      if (newOauth2Config != null) {
        newOauth2Config.setOrganization(this);
      }
    }
  }

  /**
   * Provides a concise string representation of the Organization, useful for logging.
   * Excludes collections and related config objects to avoid excessive output and recursion.
   *
   * @return A string representation of the organization.
   */
  @Override
  public String toString() {
    return "Organization{" +
            "id=" + id +
            ", orgName='" + orgName + '\'' +
            ", orgDomain='" + orgDomain + '\'' +
            ", loginType=" + loginType +
            ", isSuperOrg=" + isSuperOrg +
            ", createdBy='" + createdBy + '\'' + // Include basic audit info
            ", createdDate=" + createdDate +
            '}';
  }
}