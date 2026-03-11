// File: src/main/java/org/example/iam/repository/SamlConfigRepository.java
package org.example.iam.repository;

import org.example.iam.entity.Organization;
import org.example.iam.entity.SamlConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List; // Import List if needed for future methods
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository interface for the {@link SamlConfig} entity.
 * Provides methods for CRUD operations and custom queries related to SAML 2.0 Service Provider
 * configurations linked to organizations.
 */
@Repository
public interface SamlConfigRepository extends JpaRepository<SamlConfig, UUID> { // Primary key type is UUID

  /**
   * Finds the SAML configuration associated with a specific {@link Organization} entity.
   * As the relationship is One-to-One mapped by {@code organization_id} with a unique constraint,
   * this will return at most one result.
   *
   * @param organization The Organization entity instance.
   * @return An {@link Optional} containing the {@link SamlConfig} if found, or empty otherwise.
   */
  Optional<SamlConfig> findByOrganization(Organization organization);

  /**
   * Finds the SAML configuration by the associated Organization's unique identifier (UUID).
   * Useful for retrieving the configuration when only the organization ID is known.
   *
   * @param organizationId The UUID of the Organization.
   * @return An {@link Optional} containing the {@link SamlConfig} if found, or empty otherwise.
   */
  Optional<SamlConfig> findByOrganizationId(UUID organizationId);

  /**
   * Finds the SAML configuration by its unique Service Provider Entity ID.
   * This can be useful in SAML processing flows where the SP Entity ID is known.
   * Note: While `sp_entity_id` might not have a unique constraint globally (if different orgs
   * could hypothetically use the same ID with different IdPs - though unlikely recommended),
   * this method assumes it's reasonably unique in practice or retrieves the first match.
   *
   * @param serviceProviderEntityId The SP Entity ID string to search for.
   * @return An {@link Optional} containing the {@link SamlConfig} if found, or empty otherwise.
   */
  Optional<SamlConfig> findByServiceProviderEntityId(String serviceProviderEntityId);

  /**
   * Checks if a SAML configuration record exists for a given organization ID.
   * More efficient than fetching the entire entity if only existence is needed.
   *
   * @param organizationId The UUID of the organization.
   * @return {@code true} if a SAML configuration exists for the organization, {@code false} otherwise.
   */
  boolean existsByOrganizationId(UUID organizationId);

  /**
   * --- ADDED/UPDATED THIS METHOD ---
   * Finds all enabled configurations and forces an immediate load of the Organization entity.
   * This prevents 'no Session' LazyInitializationExceptions during application startup.
   */
  @Query("SELECT s FROM SamlConfig s JOIN FETCH s.organization WHERE s.enabled = true")
  List<SamlConfig> findByEnabledTrueWithOrganization();

  /**
   * Finds all SAML configurations that are marked as enabled.
   * Useful for loading only active configurations at startup or for administrative views.
   *
   * @return A list of all enabled {@link SamlConfig} entities.
   */
  List<SamlConfig> findByEnabledTrue(); // Added method to find enabled configs

  // JpaRepository provides standard methods like findById(UUID id), findAll(), save(S entity), delete(T entity), etc.
}