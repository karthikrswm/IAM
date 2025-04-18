// File: src/main/java/org/example/iam/entity/Role.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*; // Import base Lombok annotations
import org.example.iam.audit.Auditable; // Base class for audit fields
import org.example.iam.constant.RoleType; // Enum defining standard roles
import org.hibernate.annotations.GenericGenerator;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Represents a Role within the IAM system (e.g., SUPER, ADMIN, USER).
 * Roles define sets of permissions and are assigned to Users.
 * <p>
 * This entity maps standard roles defined in {@link RoleType} to the database.
 * It extends {@link Auditable} to track creation and modification history.
 * There is a many-to-many relationship with the {@link User} entity.
 * </p>
 */
@Entity
@Table(name = "roles", indexes = {
        // Index on role_type for efficient lookup (e.g., findByRoleType)
        @Index(name = "idx_role_type", columnList = "role_type", unique = true)
})
@Getter // Lombok: Generate getters
@Setter // Lombok: Generate setters
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows copying and modifying using builder pattern
// Include ID for equality checks, call super for Auditable fields' equality
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true)
public class Role extends Auditable<String> implements Serializable { // Audited by String (username/SYSTEM)

  @Serial // Requires Java 14+
  private static final long serialVersionUID = 3L; // Basic version UID
  /**
   * Primary key (UUID) for the role.
   */
  @Id
  @GeneratedValue(generator = "UUID")
  @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
  @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
  @EqualsAndHashCode.Include // Use ID for equality checks
  private UUID id;

  /**
   * The type of the role, corresponding to the {@link RoleType} enum.
   * Stored as a string representation of the enum name (e.g., "ADMIN").
   * This column should be unique to ensure only one DB entry per standard role type.
   */
  @Enumerated(EnumType.STRING)
  @Column(name = "role_type", nullable = false, unique = true, length = 10) // Length matches enum names
  private RoleType roleType;

  /**
   * Set of users assigned this role.
   * Many-to-Many relationship: One Role can be assigned to Many Users, and vice-versa.
   * - `mappedBy = "roles"`: Indicates the `roles` field in the `User` entity owns the relationship
   * (maintains the join table).
   * - `Workspace = FetchType.LAZY`: Users are not loaded automatically when the Role is fetched.
   */
  @ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY)
  @ToString.Exclude // Avoid recursion and large output in toString
  @Builder.Default // Initialize the set using the builder's default
  private Set<User> users = new HashSet<>();

  /**
   * Convenience constructor to create a Role directly from a RoleType.
   *
   * @param roleType The {@link RoleType} enum constant.
   */
  public Role(RoleType roleType) {
    if (roleType == null) {
      throw new IllegalArgumentException("RoleType cannot be null");
    }
    this.roleType = roleType;
  }

  /**
   * Gets the standardized role name string (e.g., "ROLE_SUPER", "ROLE_ADMIN")
   * as defined in the {@link RoleType} enum. Returns null if roleType is not set.
   * This is typically used for Spring Security integration.
   *
   * @return The standard role name string, or null.
   */
  public String getName() {
    return this.roleType != null ? this.roleType.getRoleName() : null;
  }

  /**
   * Internal package-private getter for managing the user collection.
   * Helps avoid potential infinite loops in relationship management methods
   * if User's convenience methods also directly access Role's user set via public getter.
   *
   * @return The set of users associated with this role.
   */
  Set<User> getUsersInternal() {
    return users;
  }

  /**
   * Provides a concise string representation of the Role, useful for logging.
   * Excludes the potentially large set of users.
   *
   * @return A string representation of the role.
   */
  @Override
  public String toString() {
    return "Role{" +
            "id=" + id +
            ", roleType=" + roleType +
            // Optionally include audit info if needed
            // ", createdDate=" + createdDate +
            '}';
  }
}