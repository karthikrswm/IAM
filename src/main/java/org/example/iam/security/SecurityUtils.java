// File: src/main/java/org/example/iam/security/SecurityUtils.java
package org.example.iam.security;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.RoleType;
import org.example.iam.entity.Organization; // Import needed for org ID mapping
import org.example.iam.entity.User; // Import needed for User entity casting
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Objects; // Import Objects
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Utility class providing helper methods for accessing information from the
 * Spring Security context ({@link SecurityContextHolder}).
 * <p>
 * Offers convenient and safe ways to retrieve the current {@link Authentication},
 * principal (as {@link Object}, {@link UserDetails}, or {@link User}), username,
 * user ID, organization ID, and roles, using {@link Optional} to handle cases where
 * security context information might be absent (e.g., unauthenticated requests).
 * </p>
 * Annotated with {@link UtilityClass} from Lombok to make it a final class with a
 * private constructor and static methods.
 */
@UtilityClass // Lombok: Makes class final, constructor private, all methods static.
@Slf4j
public class SecurityUtils {

  /**
   * Retrieves the current Authentication object from the SecurityContext.
   * Filters out unauthenticated Authentication objects.
   *
   * @return An Optional containing the authenticated Authentication, or empty if none is found or not authenticated.
   */
  public static Optional<Authentication> getCurrentAuthentication() {
    return Optional.ofNullable(SecurityContextHolder.getContext())
            .map(SecurityContext::getAuthentication)
            .filter(Authentication::isAuthenticated); // Only return if actually authenticated
  }

  /**
   * Retrieves the current principal object from the authenticated Authentication.
   * The type of the principal depends on how authentication was performed
   * (e.g., UserDetails, String, custom object).
   *
   * @return An Optional containing the principal object, or empty if no authenticated principal exists.
   */
  public static Optional<Object> getCurrentPrincipal() {
    return getCurrentAuthentication().map(Authentication::getPrincipal);
  }

  /**
   * Retrieves the current principal as a UserDetails object, if possible.
   * Filters the principal to ensure it's an instance of UserDetails.
   *
   * @return An Optional containing the UserDetails principal, or empty if the principal is not UserDetails or doesn't exist.
   */
  public static Optional<UserDetails> getCurrentUserDetails() {
    return getCurrentPrincipal()
            .filter(UserDetails.class::isInstance)
            .map(UserDetails.class::cast);
  }

  /**
   * Retrieves the current principal as our custom User entity object, if possible.
   * Filters the principal to ensure it's an instance of {@link User}.
   * This is useful when the {@code UserDetailsService} returns our {@code User} entity directly.
   *
   * @return An Optional containing the User entity principal, or empty if the principal is not a User or doesn't exist.
   */
  public static Optional<User> getCurrentUserEntity() {
    return getCurrentPrincipal()
            .filter(User.class::isInstance)
            .map(User.class::cast);
  }

  /**
   * Retrieves the username (name) of the currently authenticated principal.
   * This typically corresponds to {@link UserDetails#getUsername()}.
   *
   * @return An Optional containing the username string, or empty if not authenticated.
   */
  public static Optional<String> getCurrentUsername() {
    // Use Authentication::getName for standard way to get username/subject
    return getCurrentAuthentication().map(Authentication::getName);
  }

  /**
   * Retrieves the UUID of the currently authenticated user, assuming the principal is our User entity.
   *
   * @return An Optional containing the user's UUID, or empty if the principal is not a User entity or not authenticated.
   */
  public static Optional<UUID> getCurrentUserId() {
    return getCurrentUserEntity().map(User::getId);
  }

  /**
   * Retrieves the UUID of the organization the currently authenticated user belongs to,
   * assuming the principal is our User entity and it has an associated Organization.
   *
   * @return An Optional containing the organization's UUID, or empty if the user, organization, or authentication is missing.
   */
  public static Optional<UUID> getCurrentOrgId() {
    return getCurrentUserEntity()
            .map(User::getOrganization) // Get the Organization object
            .map(Organization::getId); // Get the ID from the Organization
  }

  /**
   * Retrieves the set of assigned roles (as {@link RoleType} enums) for the currently authenticated user.
   * Maps the string authorities provided by Spring Security (e.g., "ROLE_ADMIN") back to the RoleType enum.
   * Handles potential mismatches gracefully by logging a warning.
   *
   * @return A Set containing the RoleType enums corresponding to the user's authorities, or an empty set if none found or not authenticated.
   */
  public static Set<RoleType> getCurrentUserRoles() {
    return getCurrentAuthentication()
            .map(Authentication::getAuthorities) // Get Collection<? extends GrantedAuthority>
            .map(authorities -> authorities.stream()
                    .map(GrantedAuthority::getAuthority) // Get role name string (e.g., "ROLE_ADMIN")
                    .map(roleName -> {
                      try {
                        // Attempt to convert string back to RoleType enum
                        return RoleType.fromRoleName(roleName);
                      } catch (IllegalArgumentException e) {
                        // Log if a GrantedAuthority string doesn't map to a known RoleType
                        log.warn("Could not map authority string '{}' to a known RoleType enum.", roleName);
                        return null; // Return null for unmappable roles
                      }
                    })
                    .filter(Objects::nonNull) // Filter out any nulls resulting from mapping failures
                    .collect(Collectors.toSet()))
            .orElse(Collections.emptySet()); // Return empty set if no authentication or authorities
  }

  /**
   * Checks if the currently authenticated user has the specified role.
   *
   * @param roleType The {@link RoleType} to check for.
   * @return {@code true} if the user is authenticated and has the specified role, {@code false} otherwise.
   */
  public static boolean hasRole(RoleType roleType) {
    if (roleType == null) {
      return false; // Cannot have a null role
    }
    // Get the current roles and check if the set contains the specified roleType
    return getCurrentUserRoles().contains(roleType);
  }
}