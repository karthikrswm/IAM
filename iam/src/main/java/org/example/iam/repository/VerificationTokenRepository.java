// File: src/main/java/org/example/iam/repository/VerificationTokenRepository.java
package org.example.iam.repository;

import org.example.iam.entity.User;
import org.example.iam.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional; // Context: Modifying queries often called within transactions

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository interface for the {@link VerificationToken} entity.
 * Provides methods for CRUD operations and custom queries related to verification tokens
 * used for email verification and password reset.
 */
@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> { // Primary key type is UUID

  /**
   * Finds a verification token by its unique token string.
   * This is the primary method used when processing a token link clicked by a user.
   *
   * @param token The unique token string to search for.
   * @return An {@link Optional} containing the {@link VerificationToken} if found, or empty otherwise.
   */
  Optional<VerificationToken> findByToken(String token);

  /**
   * Finds the most recent verification token for a specific user and token type.
   * Useful for checking if a valid token of a certain type already exists for a user.
   * Note: Assumes only one active token per type per user should exist; older ones should be deleted/invalidated.
   *
   * @param user      The {@link User} entity instance.
   * @param tokenType The {@link VerificationToken.TokenType} enum value.
   * @return An {@link Optional} containing the {@link VerificationToken} if found.
   */
  Optional<VerificationToken> findByUserAndTokenType(User user, VerificationToken.TokenType tokenType);


  /**
   * Deletes all verification tokens associated with a specific user.
   * Useful when a user account is deleted.
   * Requires a transaction.
   *
   * @param user The {@link User} entity whose tokens should be deleted.
   * @return The number of tokens deleted.
   */
  @Modifying // Indicates this query modifies data
  // Consider service layer transaction management for atomicity with user deletion
  @Query("DELETE FROM VerificationToken vt WHERE vt.user = :user")
  int deleteByUser(@Param("user") User user);

  /**
   * Deletes all verification tokens for a specific user and token type.
   * Useful for invalidating old tokens when a new one of the same type is generated
   * (e.g., requesting a new password reset link invalidates the previous one).
   * Requires a transaction.
   *
   * @param user      The {@link User} entity.
   * @param tokenType The {@link VerificationToken.TokenType} to delete.
   * @return The number of tokens deleted.
   */
  @Modifying
  // Service layer should manage transaction
  @Query("DELETE FROM VerificationToken vt WHERE vt.user = :user AND vt.tokenType = :tokenType")
  int deleteByUserAndTokenType(@Param("user") User user, @Param("tokenType") VerificationToken.TokenType tokenType);

  /**
   * Deletes all verification tokens whose expiry date is less than or equal to the provided timestamp.
   * Used by a background scheduler ({@link org.example.iam.service.UserAccountScheduler}) to clean up expired tokens.
   * Requires a transaction.
   *
   * @param now The timestamp threshold; tokens expired at or before this time will be deleted.
   * @return The number of expired tokens deleted.
   */
  @Modifying
  // Service layer (scheduler) should manage transaction
  @Query("DELETE FROM VerificationToken vt WHERE vt.expiryDate <= :now")
  int deleteAllExpiredSince(@Param("now") Instant now);

  /**
   * Finds all verification tokens whose expiry date is less than or equal to the provided timestamp.
   * Can be used for reporting or manual cleanup checks, though deleteAllExpiredSince is typical for automated cleanup.
   *
   * @param now The timestamp threshold.
   * @return A list of expired {@link VerificationToken} entities.
   */
  @Query("SELECT vt FROM VerificationToken vt WHERE vt.expiryDate <= :now")
  List<VerificationToken> findAllExpiredSince(@Param("now") Instant now);

  // JpaRepository provides standard methods like findById(UUID id), findAll(), save(S entity), delete(T entity), etc.
}