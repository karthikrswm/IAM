// File: src/main/java/org/example/iam/constant/RoleType.java
package org.example.iam.constant;

import lombok.Getter; // Added Getter

/**
 * Defines the standard user roles within the IAM system.
 * Each role corresponds to a level of permissions and access.
 * Roles are typically persisted in the database (see {@link org.example.iam.entity.Role})
 * and linked to users.
 */
@Getter // Generates getName() implicitly used by fromRoleName and elsewhere
public enum RoleType {
  /**
   * Highest privilege role, typically managing the entire IAM system,
   * including creating/managing other organizations and super users.
   * Usually associated with the Super Organization.
   * Standard Spring Security representation: "ROLE_SUPER".
   */
  SUPER("ROLE_SUPER"),

  /**
   * Administrator role within a specific Organization.
   * Can manage users and potentially configurations within their own organization.
   * Standard Spring Security representation: "ROLE_ADMIN".
   */
  ADMIN("ROLE_ADMIN"),

  /**
   * Standard user role within a specific Organization.
   * Basic access permissions, typically managed by ADMINs of the organization.
   * Standard Spring Security representation: "ROLE_USER".
   */
  USER("ROLE_USER");

  /**
   * The string representation of the role name, conventionally used by Spring Security
   * (prefixed with "ROLE_").
   */
  private final String roleName;

  /**
   * Enum constructor.
   *
   * @param roleName The standard role name string (e.g., "ROLE_ADMIN").
   */
  RoleType(String roleName) {
    this.roleName = roleName;
  }

  /**
   * Finds a RoleType enum constant based on its standard role name string (case-insensitive).
   * Useful for converting role strings (e.g., from JWT claims or database) back to the enum type.
   *
   * @param roleName The role name string (e.g., "ROLE_ADMIN", "ADMIN", "role_admin").
   * @return The matching RoleType enum constant.
   * @throws IllegalArgumentException if no matching RoleType is found for the given name.
   */
  public static RoleType fromRoleName(String roleName) {
    if (roleName == null || roleName.trim().isEmpty()) {
      throw new IllegalArgumentException("Role name cannot be null or empty.");
    }
    for (RoleType type : RoleType.values()) {
      // Compare ignoring case for flexibility
      if (type.getRoleName().equalsIgnoreCase(roleName) ||
              type.name().equalsIgnoreCase(roleName)) { // Also allow matching enum name itself (e.g., "ADMIN")
        return type;
      }
    }
    // If no match found after checking standard name and enum name
    throw new IllegalArgumentException("No matching RoleType found for role name: " + roleName);
  }
}