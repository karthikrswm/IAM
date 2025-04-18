// File: src/main/java/org/example/iam/service/NotificationService.java
package org.example.iam.service;

import org.example.iam.entity.User;

import java.util.List; // <<< ADDED import

/**
 * Interface defining the contract for sending various notifications to users and administrators.
 * <p>
 * This decouples the notification mechanism (e.g., email, SMS, push notification)
 * from the core business logic services (like {@link AuthService} or {@link UserService})
 * that need to trigger these notifications.
 * </p>
 * <p>
 * Implementations of this interface (e.g., {@link EmailNotificationService}) will handle
 * the specifics of message formatting and delivery via the chosen channel.
 * Methods are typically expected to be executed asynchronously to avoid blocking
 * the calling thread.
 * </p>
 */
public interface NotificationService {

  /**
   * Sends an email verification notification to the user.
   * This email typically contains instructions and a unique verification link (token)
   * for the user to click to confirm their email address and activate their account.
   * It may also include temporary password information if applicable (handle securely!).
   *
   * @param user              The newly created or registered user requiring verification.
   * @param verificationToken The unique verification token string to include in the link.
   * @param temporaryPassword (Optional) The temporary password assigned to the user.
   * Implementations should handle this securely, considering the risks
   * of sending passwords via email. Null if not applicable.
   */
  void sendVerificationEmail(User user, String verificationToken, String temporaryPassword);

  /**
   * Sends a password reset notification to the user after they initiate the "forgot password" process.
   * This email contains instructions and a unique link (including the reset token) that allows
   * the user to access a page where they can set a new password.
   *
   * @param user       The user requesting the password reset.
   * @param resetToken The unique password reset token string to include in the link.
   */
  void sendPasswordResetEmail(User user, String resetToken);

  /**
   * Sends a notification to the user confirming that their password has been successfully changed.
   * This serves as a security alert in case the user did not initiate the change themselves.
   *
   * @param user The user whose password was changed.
   */
  void sendPasswordChangeConfirmationEmail(User user);

  /**
   * Sends a notification to the user informing them that their account has been temporarily locked,
   * usually due to excessive failed login attempts.
   * It may optionally include information about the lock duration or how to unlock the account.
   *
   * @param user The user whose account was locked.
   */
  void sendAccountLockedEmail(User user);

  /**
   * Sends a warning notification to the user that their password will expire soon.
   *
   * @param user            The user whose password is about to expire.
   * @param daysUntilExpiry The number of days remaining until the password expires.
   */
  void sendPasswordExpiryWarningEmail(User user, long daysUntilExpiry); // <<< ADDED Method

  /**
   * Sends a notification to the user that their password has expired.
   *
   * @param user The user whose password has expired.
   */
  void sendPasswordExpiredEmail(User user); // <<< ADDED Method

  /**
   * Sends a notification to the administrators of an organization that a user's password has expired.
   *
   * @param expiredUser The user whose password has expired.
   * @param orgAdmins   A list of User entities representing the administrators of the organization.
   */
  void sendAdminPasswordExpiredNotification(User expiredUser, List<User> orgAdmins); // <<< ADDED Method


  // Add other notification methods as needed, for example:
  // void sendAccountUnlockedEmail(User user);
  // void sendAccountDisabledNotification(User user, String reason);
  // void sendMfaCode(User user, String code, NotificationChannel channel); // e.g., channel = SMS, EMAIL
}