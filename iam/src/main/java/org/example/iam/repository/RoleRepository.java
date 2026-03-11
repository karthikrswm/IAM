// File: src/main/java/org/example/iam/repository/RoleRepository.java
package org.example.iam.repository;

import org.example.iam.constant.RoleType; // Enum defining standard roles
import org.example.iam.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository interface for the {@link Role} entity.
 * Provides methods for CRUD operations and finding roles based on their type.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> { // Primary key type is UUID

  /**
   * Finds a role entity based on its {@link RoleType} enum value.
   * Since {@code role_type} has a unique constraint in the database schema, this method
   * is guaranteed to return at most one role.
   * <p>
   * This is the primary method used to retrieve standard roles (SUPER, ADMIN, USER)
   * when assigning them to users.
   * </p>
   *
   * @param roleType The {@link RoleType} enum constant representing the desired role.
   * @return An {@link Optional} containing the {@link Role} entity if found, or empty otherwise.
   */
  Optional<Role> findByRoleType(RoleType roleType);

  // JpaRepository provides standard methods like findById(UUID id), findAll(), save(S entity), etc.
  // No other custom queries seem necessary for the Role entity at this time.
}