// File: src/main/java/org/example/iam/entity/User.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*; // Import base Lombok annotations
import org.example.iam.audit.Auditable; // Base class for audit fields
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails; // Interface for Spring Security

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Represents a User account within the IAM system.
 * <p>
 * Each user belongs to exactly one {@link Organization} and can have multiple {@link Role} assignments.
 * This entity implements Spring Security's {@link UserDetails} interface, allowing it to be
 * directly used by the authentication mechanisms (like {@link org.example.iam.service.UserDetailsServiceImp}).
 * </p>
 * <p>
 * It extends {@link Auditable} to track creation and modification history.
 * Includes fields for managing account status (enabled, locked, expired) and login tracking.
 * </p>
 */
@Entity
@Table(name = "users", uniqueConstraints = {
        // Ensure username and primary email are unique across the system
        @UniqueConstraint(columnNames = "username", name = "uk_user_username"),
        @UniqueConstraint(columnNames = "primary_email", name = "uk_user_primary_email")
}, indexes = {
        // Index for quick lookup by organization ID
        @Index(name = "idx_user_organization_id", columnList = "organization_id"),
        // Index for scheduler queries on locked accounts
        @Index(name = "idx_user_lock_status_time", columnList = "account_non_locked, lock_time"),
        // Index for scheduler queries on credentials expiration
        @Index(name = "idx_user_cred_status_pwd_change", columnList = "credentials_non_expired, password_changed_date"),
        // Index for scheduler queries on inactivity
        @Index(name = "idx_user_enabled_last_login", columnList = "enabled, last_login_date")
})
@Getter // Lombok: Generate getters for all fields (including UserDetails methods like isEnabled())
@Setter // Lombok: Generate setters for all fields
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows copying and modifying using builder pattern
// Include ID for equality checks, call super for Auditable fields' equality
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true)
public class User extends Auditable<String> implements UserDetails, Serializable { // Implement UserDetails

  @Serial // Requires Java 14+
  private static final long serialVersionUID = 3L; // Basic version UID
  /**
   * Primary key (UUID) for the user account.
   */
  @Id
  @GeneratedValue(generator = "UUID")
  @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
  @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
  @EqualsAndHashCode.Include // Use ID for equality checks
  private UUID id;

  /**
   * Unique username for the user account. Used for login.
   */
  @Column(name = "username", nullable = false, unique = true, length = 50)
  private String username; // UserDetails: getUsername() provided by Lombok @Getter

  /**
   * Hashed password for the user.
   * Never stored in plain text.
   */
  @Column(name = "password", nullable = false, length = 100) // Increased length for future hash algos
  @ToString.Exclude // Do not include password hash in default toString()
  private String password; // UserDetails: getPassword() provided by Lombok @Getter

  /**
   * User's primary email address. Must be unique. Used for login and notifications.
   * Domain must match the owning organization's domain.
   */
  @Column(name = "primary_email", nullable = false, unique = true, length = 100)
  private String primaryEmail;

  /**
   * User's optional secondary email address.
   */
  @Column(name = "secondary_email", length = 100, nullable = true)
  private String secondaryEmail;

  /**
   * User's optional phone number.
   */
  @Column(name = "phone_number", length = 20, nullable = true)
  private String phoneNumber;

  /**
   * The Organization this user belongs to.
   * Many-to-One relationship: Many Users belong to One Organization.
   * - `Workspace = FetchType.LAZY`: Organization is loaded only when accessed.
   * - `optional = false`: A User must belong to an Organization.
   */
  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "organization_id", nullable = false,
          // Define foreign key constraint for clarity and DB integrity
          foreignKey = @ForeignKey(name = "fk_user_organization"))
  @ToString.Exclude // Avoid recursion in toString if Organization includes User list
  private Organization organization;

  /**
   * Set of roles assigned to this user.
   * Many-to-Many relationship defined via the `user_roles` join table.
   * - `Workspace = FetchType.EAGER`: Roles (authorities) are loaded immediately with the User.
   * This is often necessary for Spring Security's `UserDetails` contract,
   * especially if the transaction boundary ends before `getAuthorities()` is called.
   */
  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
          name = "user_roles", // Name of the intermediate join table
          joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"), // FK to this entity (User)
          inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"), // FK to the other entity (Role)
          foreignKey = @ForeignKey(name = "fk_user_roles_user"), // Constraint name for FK to users table
          inverseForeignKey = @ForeignKey(name = "fk_user_roles_role") // Constraint name for FK to roles table
  )
  @ToString.Exclude // Avoid large output in toString
  @Builder.Default // Initialize the set using the builder's default
  private Set<Role> roles = new HashSet<>();

  // --- UserDetails Fields (Account Status Flags) ---

  /**
   * Indicates whether the user's account has expired. An expired account cannot be authenticated.
   * Corresponds to {@link UserDetails#isAccountNonExpired()}.
   */
  @Column(name = "account_non_expired", nullable = false)
  @Builder.Default
  private boolean accountNonExpired = true; // Default to non-expired

  /**
   * Indicates whether the user is locked or unlocked. A locked account cannot be authenticated.
   * Corresponds to {@link UserDetails#isAccountNonLocked()}.
   */
  @Column(name = "account_non_locked", nullable = false)
  @Builder.Default
  private boolean accountNonLocked = true; // Default to non-locked

  /**
   * Indicates whether the user's credentials (password) has expired. Expired credentials prevent authentication.
   * Corresponds to {@link UserDetails#isCredentialsNonExpired()}.
   */
  @Column(name = "credentials_non_expired", nullable = false)
  @Builder.Default
  private boolean credentialsNonExpired = true; // Default to non-expired (false for newly created with temp password)

  /**
   * Indicates whether the user is enabled or disabled. A disabled account cannot be authenticated.
   * Corresponds to {@link UserDetails#isEnabled()}. Often used for email verification status.
   */
  @Column(name = "enabled", nullable = false)
  @Builder.Default
  private boolean enabled = false; // Default to disabled (requires verification)

  // --- Additional Status and Tracking Fields ---

  /**
   * Counter for consecutive failed login attempts. Used for account locking mechanism.
   */
  @Column(name = "failed_login_attempts", nullable = false)
  @Builder.Default
  private int failedLoginAttempts = 0;

  /**
   * Timestamp until which the account remains locked. Null if not locked.
   */
  @Column(name = "lock_time", nullable = true) // Changed from locked_until for clarity
  private Instant lockTime;

  /**
   * Timestamp when the user's password was last changed. Used for password expiry checks.
   */
  @Column(name = "password_changed_date", nullable = false)
  @Builder.Default
  private Instant passwordChangedDate = Instant.now(); // Set on creation/password change

  /**
   * Timestamp of the user's last successful login. Used for inactivity checks.
   */
  @Column(name = "last_login_date", nullable = true)
  private Instant lastLoginDate;

  /**
   * Flag indicating if the current password is a temporary one assigned during creation
   * or reset, requiring the user to change it upon next login.
   */
  @Column(name = "temporary_password", nullable = false)
  @Builder.Default
  private boolean temporaryPassword = true; // Default new users have temporary password

  // --- UserDetails Methods Implementation ---

  /**
   * Returns the authorities granted to the user. Cannot return {@code null}.
   * Maps the user's assigned {@link Role} entities to Spring Security's {@link GrantedAuthority}.
   * Requires roles to be fetched (FetchType.EAGER recommended).
   *
   * @return the authorities, sorted by natural key (never {@code null})
   */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    if (this.roles == null) {
      return Set.of(); // Return empty set if roles somehow null
    }
    return this.roles.stream()
            .map(role -> new SimpleGrantedAuthority(role.getName())) // Use Role's standard name (e.g., "ROLE_ADMIN")
            .collect(Collectors.toSet());
  }

  // getPassword() - Provided by Lombok @Getter
  // getUsername() - Provided by Lombok @Getter

  // isAccountNonExpired() - Provided by Lombok @Getter for boolean field 'accountNonExpired'
  // isAccountNonLocked() - Provided by Lombok @Getter for boolean field 'accountNonLocked'
  // isCredentialsNonExpired() - Provided by Lombok @Getter for boolean field 'credentialsNonExpired'
  // isEnabled() - Provided by Lombok @Getter for boolean field 'enabled'


  // --- Convenience Methods ---

  /**
   * Adds a role to the user, managing the bidirectional relationship.
   *
   * @param role The Role to add. Should not be null.
   */
  public void addRole(Role role) {
    if (role != null && this.roles.add(role)) { // Ensure role is not null and successfully added
      // Use internal getter on Role side if necessary to avoid potential infinite loops
      // depending on how Role's add/remove User methods are implemented.
      role.getUsersInternal().add(this);
    }
  }

  /**
   * Removes a role from the user, managing the bidirectional relationship.
   *
   * @param role The Role to remove. Should not be null.
   */
  public void removeRole(Role role) {
    if (role != null && this.roles.remove(role)) { // Ensure role is not null and successfully removed
      role.getUsersInternal().remove(this);
    }
  }

  /**
   * Checks if the user has a specific role assigned.
   *
   * @param roleName The standard role name string (e.g., "ROLE_ADMIN") to check for.
   * @return true if the user has the role, false otherwise.
   */
  public boolean hasRole(String roleName) {
    if (roleName == null || this.roles == null) {
      return false;
    }
    return this.roles.stream().anyMatch(role -> roleName.equals(role.getName()));
  }

  /**
   * Provides a concise string representation of the User, useful for logging.
   * Excludes sensitive information like the password and potentially large role collections.
   *
   * @return A string representation of the user.
   */
  @Override
  public String toString() {
    return "User{" +
            "id=" + id +
            ", username='" + username + '\'' +
            ", primaryEmail='" + primaryEmail + '\'' +
            ", organizationId=" + (organization != null ? organization.getId() : "null") +
            // Collect role names instead of full Role objects
            ", roles=" + (roles != null ? roles.stream().map(Role::getName).collect(Collectors.joining(", ")) : "[]") +
            ", enabled=" + enabled +
            ", accountNonLocked=" + accountNonLocked +
            ", credentialsNonExpired=" + credentialsNonExpired +
            ", createdBy='" + createdBy + '\'' +
            ", createdDate=" + createdDate +
            '}';
  }
}