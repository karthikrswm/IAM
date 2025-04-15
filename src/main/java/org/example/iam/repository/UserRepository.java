// File: src/main/java/org/example/iam/repository/UserRepository.java
package org.example.iam.repository;

import org.example.iam.entity.Organization;
import org.example.iam.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional; // Often needed at service layer, but useful context here

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository interface for the {@link User} entity.
 * Provides methods for CRUD operations and numerous custom queries for user lookup,
 * status management, and supporting background scheduler tasks.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> { // Primary key type is UUID

  // --- Standard Lookups ---

  /**
   * Finds a user by their username, ignoring case. Used for login and checking uniqueness.
   *
   * @param username The username to search for (case-insensitive).
   * @return An {@link Optional} containing the {@link User} if found.
   */
  Optional<User> findByUsernameIgnoreCase(String username);

  /**
   * Finds a user by their primary email address, ignoring case. Used for login, password reset, JIT provisioning, and checking uniqueness.
   *
   * @param primaryEmail The primary email address to search for (case-insensitive).
   * @return An {@link Optional} containing the {@link User} if found.
   */
  Optional<User> findByPrimaryEmailIgnoreCase(String primaryEmail);

  /**
   * Checks if a user exists with the given username, ignoring case.
   *
   * @param username The username to check (case-insensitive).
   * @return {@code true} if a user with the username exists, {@code false} otherwise.
   */
  boolean existsByUsernameIgnoreCase(String username);

  /**
   * Checks if a user exists with the given primary email address, ignoring case.
   *
   * @param primaryEmail The primary email address to check (case-insensitive).
   * @return {@code true} if a user with the primary email exists, {@code false} otherwise.
   */
  boolean existsByPrimaryEmailIgnoreCase(String primaryEmail);

  /**
   * Checks if a user exists with the given secondary email address, ignoring case.
   * Used to prevent assigning a secondary email that's already a primary/secondary email elsewhere,
   * especially if domain validation rules are complex.
   *
   * @param secondaryEmail The secondary email address to check (case-insensitive).
   * @return {@code true} if a user with the secondary email exists, {@code false} otherwise.
   */
  boolean existsBySecondaryEmailIgnoreCase(String secondaryEmail);

  // --- Organization-Based Lookups ---

  /**
   * Finds a paginated list of users belonging to a specific {@link Organization} entity instance.
   *
   * @param organization The Organization entity instance.
   * @param pageable     Pagination and sorting information.
   * @return A {@link Page} of {@link User} entities belonging to the organization.
   */
  Page<User> findByOrganization(Organization organization, Pageable pageable);

  /**
   * Finds a paginated list of users belonging to a specific organization identified by its UUID.
   *
   * @param organizationId The UUID of the organization.
   * @param pageable       Pagination and sorting information.
   * @return A {@link Page} of {@link User} entities belonging to the organization.
   */
  Page<User> findByOrganizationId(UUID organizationId, Pageable pageable);

  // --- Account Status Management Methods (Modifying Queries) ---

  /**
   * Updates the failed login attempt counter for a specific user identified by username (case-insensitive).
   * Intended to be called within a transaction (typically from the service layer).
   *
   * @param attempts The new value for the failed login attempt counter.
   * @param username The username of the user to update (case-insensitive).
   */
  @Modifying // Indicates this query modifies data
  @Query("UPDATE User u SET u.failedLoginAttempts = :attempts WHERE lower(u.username) = lower(:username)")
  void updateFailedAttempts(@Param("attempts") int attempts, @Param("username") String username);

  /**
   * Locks a user account identified by username (case-insensitive) by setting {@code accountNonLocked} to false
   * and recording the time until which the lock is effective.
   * Intended to be called within a transaction.
   *
   * @param username The username of the user to lock (case-insensitive).
   * @param lockTime The timestamp until which the account should remain locked.
   */
  @Modifying
  @Query("UPDATE User u SET u.accountNonLocked = false, u.lockTime = :lockTime WHERE lower(u.username) = lower(:username)")
  void lockAccount(@Param("username") String username, @Param("lockTime") Instant lockTime);

  /**
   * Unlocks a user account identified by its UUID. Sets {@code accountNonLocked} to true,
   * clears the lock time, and resets the failed login attempt counter to 0.
   * Intended to be called within a transaction.
   *
   * @param userId The UUID of the user to unlock.
   */
  @Modifying
  @Query("UPDATE User u SET u.accountNonLocked = true, u.lockTime = NULL, u.failedLoginAttempts = 0 WHERE u.id = :userId")
  void unlockAccount(@Param("userId") UUID userId);

  /**
   * Enables a user account identified by its UUID by setting the {@code enabled} flag to true.
   * Typically used after email verification.
   * Intended to be called within a transaction.
   *
   * @param userId The UUID of the user to enable.
   */
  @Modifying
  @Query("UPDATE User u SET u.enabled = true WHERE u.id = :userId")
  void enableUser(@Param("userId") UUID userId);

  /**
   * Disables a user account identified by its UUID by setting the {@code enabled} flag to false.
   * Used by administrators or schedulers (e.g., for inactivity).
   * Intended to be called within a transaction.
   *
   * @param userId The UUID of the user to disable.
   */
  @Modifying
  @Query("UPDATE User u SET u.enabled = false WHERE u.id = :userId")
  void disableUser(@Param("userId") UUID userId);

  // --- Queries for Background Schedulers ---

  /**
   * Finds users whose accounts are currently locked (accountNonLocked = false)
   * and whose lock time has passed or is equal to the specified time ('now').
   * Used by the account unlock scheduler.
   *
   * @param now The current timestamp to compare against the lock time.
   * @return A list of {@link User} entities eligible for unlocking.
   */
  @Query("SELECT u FROM User u WHERE u.accountNonLocked = false AND u.lockTime IS NOT NULL AND u.lockTime <= :now")
  List<User> findLockedUsersWithExpiredLockTime(@Param("now") Instant now);

  /**
   * Finds users who are currently enabled, do not belong to the Super Organization,
   * and whose last login date is either null or before the specified inactivity threshold.
   * Used by the inactivity check scheduler. Excludes Super Org users from inactivity checks.
   *
   * @param inactivityThreshold The timestamp defining the inactivity period cutoff.
   * @return A list of {@link User} entities considered inactive.
   */
  @Query("SELECT u FROM User u WHERE u.enabled = true AND u.organization.isSuperOrg = false AND (u.lastLoginDate IS NULL OR u.lastLoginDate < :inactivityThreshold)")
  List<User> findUsersForInactivityCheck(@Param("inactivityThreshold") Instant inactivityThreshold);

  /**
   * Finds users whose credentials (password) are currently marked as non-expired but
   * whose password was last changed before the specified expiration threshold date.
   * Used by the password expiration scheduler.
   *
   * @param expirationThresholdDate The timestamp defining the password age cutoff.
   * @return A list of {@link User} entities whose credentials should be marked as expired.
   */
  @Query("SELECT u FROM User u WHERE u.credentialsNonExpired = true AND u.passwordChangedDate < :expirationThresholdDate")
  List<User> findUsersWithExpiringCredentials(@Param("expirationThresholdDate") Instant expirationThresholdDate);

  /**
   * Updates the {@code credentialsNonExpired} status for a specific user identified by UUID.
   * Used by the password expiration scheduler.
   * Intended to be called within a transaction.
   *
   * @param userId The UUID of the user to update.
   * @param status The new status for {@code credentialsNonExpired} (typically false when expiring).
   */
  @Modifying
  @Query("UPDATE User u SET u.credentialsNonExpired = :status WHERE u.id = :userId")
  void updateCredentialsExpiredStatus(@Param("userId") UUID userId, @Param("status") boolean status);

  /**
   * Updates the last login timestamp for a specific user identified by UUID.
   * Called upon successful user login.
   * Intended to be called within a transaction.
   *
   * @param userId        The UUID of the user whose last login date is being updated.
   * @param lastLoginDate The timestamp of the successful login.
   */
  @Modifying
  @Query("UPDATE User u SET u.lastLoginDate = :lastLoginDate WHERE u.id = :userId")
  void updateLastLoginDate(@Param("userId") UUID userId, @Param("lastLoginDate") Instant lastLoginDate);


  /**
   * Updates a user's password hash, marks the password as non-temporary, updates the
   * password changed date, and ensures credentials are marked as non-expired.
   * Used during password reset or initial password change flows.
   * Intended to be called within a transaction.
   *
   * @param userId            The UUID of the user whose password is being updated.
   * @param encodedPassword   The new, securely hashed password.
   * @param changeDate        The timestamp when the password change occurred.
   */
  @Modifying
  @Query("UPDATE User u SET u.password = :password, u.temporaryPassword = false, u.passwordChangedDate = :changeDate, u.credentialsNonExpired = true WHERE u.id = :userId")
  void updateUserPassword(@Param("userId") UUID userId, @Param("password") String encodedPassword, @Param("changeDate") Instant changeDate);

}