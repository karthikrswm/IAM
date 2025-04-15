// File: src/main/java/org/example/iam/repository/Oauth2ConfigRepository.java
package org.example.iam.repository;

import org.example.iam.entity.Oauth2Config;
import org.example.iam.entity.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List; // Import List if needed for future methods
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository interface for the {@link Oauth2Config} entity.
 * Provides methods for CRUD operations and custom queries related to OAuth2 configurations
 * linked to organizations.
 */
@Repository
public interface Oauth2ConfigRepository extends JpaRepository<Oauth2Config, UUID> { // Primary key type is UUID

  /**
   * Finds the OAuth2 configuration associated with a specific {@link Organization} entity.
   * As the relationship is One-to-One mapped by {@code organization_id} with a unique constraint,
   * this will return at most one result.
   *
   * @param organization The Organization entity instance.
   * @return An {@link Optional} containing the {@link Oauth2Config} if found, or empty otherwise.
   */
  Optional<Oauth2Config> findByOrganization(Organization organization);

  /**
   * Finds the OAuth2 configuration by the associated Organization's unique identifier (UUID).
   * Useful for retrieving the configuration when only the organization ID is known.
   *
   * @param organizationId The UUID of the Organization.
   * @return An {@link Optional} containing the {@link Oauth2Config} if found, or empty otherwise.
   */
  Optional<Oauth2Config> findByOrganizationId(UUID organizationId);

  /**
   * Checks if an OAuth2 configuration record exists for a given organization ID.
   * More efficient than fetching the entire entity if only existence is needed.
   *
   * @param organizationId The UUID of the organization.
   * @return {@code true} if an OAuth2 configuration exists for the organization, {@code false} otherwise.
   */
  boolean existsByOrganizationId(UUID organizationId);

  /**
   * Finds the OAuth2 configuration based on both the organization ID and the provider identifier string
   * (case-insensitive comparison for the provider).
   * <p>
   * While typically there's only one OAuth2 config per organization due to the unique constraint
   * on `organization_id`, this method could be useful if the model were adapted to allow multiple
   * providers per organization (though that would require schema changes). Currently, it primarily serves
   * as an alternative way to fetch the single config if the provider name is also known.
   * </p>
   *
   * @param organizationId The UUID of the organization.
   * @param provider       The provider identifier string (e.g., "google", "github"). Comparison is case-insensitive.
   * @return An {@link Optional} containing the specific {@link Oauth2Config} if found.
   */
  Optional<Oauth2Config> findByOrganizationIdAndProviderIgnoreCase(UUID organizationId, String provider);

  /**
   * Finds all OAuth2 configurations that are marked as enabled.
   * Useful for loading only active configurations at startup or for administrative views.
   *
   * @return A list of all enabled {@link Oauth2Config} entities.
   */
  List<Oauth2Config> findByEnabledTrue(); // Added method to find enabled configs

}