// File: src/main/java/org/example/iam/repository/OrganizationRepository.java
package org.example.iam.repository;

import org.example.iam.entity.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository interface for the {@link Organization} entity.
 * Provides methods for CRUD operations and custom queries related to organizations (tenants).
 */
@Repository
public interface OrganizationRepository extends JpaRepository<Organization, UUID> { // Primary key type is UUID

  /**
   * Finds an organization by its primary domain name, ignoring case.
   * Useful for checking domain uniqueness or looking up an organization by its domain.
   *
   * @param orgDomain The domain name to search for (case-insensitive).
   * @return An {@link Optional} containing the {@link Organization} if found, or empty otherwise.
   */
  Optional<Organization> findByOrgDomainIgnoreCase(String orgDomain);

  /**
   * Finds an organization by its name, ignoring case.
   * Useful for checking name uniqueness or looking up an organization by its name.
   *
   * @param orgName The organization name to search for (case-insensitive).
   * @return An {@link Optional} containing the {@link Organization} if found, or empty otherwise.
   */
  Optional<Organization> findByOrgNameIgnoreCase(String orgName);

  /**
   * Checks if an organization exists with the given primary domain name, ignoring case.
   * More efficient than fetching the entity if only existence check is needed.
   *
   * @param orgDomain The domain name to check (case-insensitive).
   * @return {@code true} if an organization with the domain exists, {@code false} otherwise.
   */
  boolean existsByOrgDomainIgnoreCase(String orgDomain);

  /**
   * Checks if an organization exists with the given name, ignoring case.
   * More efficient than fetching the entity if only existence check is needed.
   *
   * @param orgName The organization name to check (case-insensitive).
   * @return {@code true} if an organization with the name exists, {@code false} otherwise.
   */
  boolean existsByOrgNameIgnoreCase(String orgName);

  /**
   * Finds the unique "Super Organization" by checking the {@code isSuperOrg} flag.
   * Assumes there is only one such organization in the system.
   *
   * @return An {@link Optional} containing the Super Organization if found, or empty otherwise.
   */
  Optional<Organization> findByIsSuperOrgTrue();

  // JpaRepository provides standard methods like findById(UUID id), findAll(), save(S entity), delete(T entity), etc.
}