// File: src/main/java/org/example/iam/entity/VerificationToken.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.iam.audit.Auditable; // Base class for audit fields
import org.hibernate.annotations.GenericGenerator;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a time-limited token used for verifying specific actions, such as
 * email address confirmation or password reset requests.
 * <p>
 * Each token is associated with a {@link User}, has a specific {@link TokenType},
 * a unique secure token string, and an expiry date.
 * </p>
 * <p>
 * It extends {@link Auditable} to track creation and modification history, although typically
 * tokens are created and deleted rather than modified.
 * </p>
 */
@Entity
@Table(name = "verification_tokens", indexes = {
        // Index for fast lookup by the token string (most common use case)
        @Index(name = "idx_verification_token", columnList = "token", unique = true),
        // Index for finding/deleting tokens for a specific user and type
        // (e.g., invalidate old password reset tokens when a new one is requested)
        @Index(name = "idx_verification_user_type", columnList = "user_id, token_type"),
        // Index for scheduler cleanup based on expiry date
        @Index(name = "idx_verification_expiry_date", columnList = "expiry_date")
})
@Getter
@Setter
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows copying and modifying using builder pattern
// Include ID for equality checks, call super for Auditable fields' equality
@EqualsAndHashCode(callSuper = true, onlyExplicitlyIncluded = true)
public class VerificationToken extends Auditable<String> { // Audited by String (username/SYSTEM)

  /**
   * Primary key (UUID) for the verification token record.
   */
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
  @EqualsAndHashCode.Include // Use ID for equality checks
  private UUID id;

  /**
   * The secure, unique, randomly generated token string provided to the user.
   */
  @Column(name = "token", nullable = false, unique = true, length = 100) // Ensure uniqueness
  @ToString.Exclude // Exclude the actual token value from default toString() for security
  private String token;

  /**
   * The User account associated with this verification token.
   * Many-to-One relationship: Many tokens can belong to one User.
   * - `Workspace = FetchType.LAZY`: User is loaded only when explicitly accessed.
   * - `optional = false`: A token must belong to a user.
   */
  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "user_id", nullable = false,
          foreignKey = @ForeignKey(name = "fk_token_user")) // Define foreign key constraint name
  @ToString.Exclude // Avoid potential recursion if User includes tokens
  private User user;

  /**
   * The purpose of this token, distinguishing between different verification flows.
   * Stored as a string representation of the {@link TokenType} enum.
   */
  @Enumerated(EnumType.STRING)
  @Column(name = "token_type", nullable = false, length = 20) // Length fits enum names
  private TokenType tokenType; // Type of token (EMAIL_VERIFICATION, PASSWORD_RESET)

  /**
   * The exact timestamp after which this token is no longer valid. Uses UTC.
   */
  @Column(name = "expiry_date", nullable = false)
  private Instant expiryDate;

  // --- Convenience Methods ---

  /**
   * Checks if the token has expired based on the current system time (Instant.now()).
   *
   * @return {@code true} if the current time is after the token's expiry date, {@code false} otherwise.
   */
  public boolean isExpired() {
    return Instant.now().isAfter(this.expiryDate);
  }

  /**
   * Provides a concise string representation of the VerificationToken, useful for logging.
   * Excludes the actual token string for security reasons.
   *
   * @return A string representation of the token metadata.
   */
  @Override
  public String toString() {
    // Avoid logging the actual token string for security.
    // Avoid loading user eagerly just for toString if fetch is LAZY.
    return "VerificationToken{" +
            "id=" + id +
            ", userId=" + (user != null ? user.getId() : "null") + // Show user ID if loaded, else null
            ", tokenType=" + tokenType +
            ", expiryDate=" + expiryDate +
            ", createdDate=" + createdDate +
            '}';
  }

  /**
   * Enum defining the different purposes a verification token can serve within the system.
   */
  public enum TokenType {
    /**
     * Token used to verify a user's email address, typically after registration or email change.
     */
    EMAIL_VERIFICATION,

    /**
     * Token used to allow a user to reset their password after initiating the "forgot password" flow.
     */
    PASSWORD_RESET
  }
}