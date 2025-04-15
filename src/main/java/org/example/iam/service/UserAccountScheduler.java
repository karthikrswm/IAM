// File: src/main/java/org/example/iam/service/UserAccountScheduler.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.audit.AuditorAwareImpl; // To get SYSTEM auditor constant
import org.example.iam.constant.AuditEventType;
// No need for RoleType here
import org.example.iam.entity.User;
import org.example.iam.repository.UserRepository;
import org.example.iam.repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional; // Needed for DB operations

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Component containing scheduled tasks related to user account maintenance and status updates.
 * These tasks run periodically based on configured cron expressions to perform actions like:
 * - Unlocking accounts locked due to failed login attempts after a duration.
 * - Marking user credentials (passwords) as expired based on age.
 * - Disabling accounts due to prolonged inactivity.
 * - Cleaning up expired verification/password reset tokens.
 * <p>
 * Uses {@link Scheduled @Scheduled} annotation and requires scheduling to be enabled
 * (via {@link org.springframework.scheduling.annotation.EnableScheduling @EnableScheduling}
 * on a configuration class like {@link org.example.iam.config.SchedulerConfig}).
 * </p>
 * <p>
 * Operations modifying user or token data are performed within transactions.
 * Audit events are logged using the {@link AuditorAwareImpl#SYSTEM_AUDITOR} identifier.
 * </p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class UserAccountScheduler {

  private static final String SYSTEM_ACTOR = AuditorAwareImpl.SYSTEM_AUDITOR; // Standard identifier for system actions

  // --- Dependencies ---
  private final UserRepository userRepository;
  private final VerificationTokenRepository tokenRepository;
  private final AuditEventService auditEventService;
  // private final NotificationService notificationService; // Inject if notifications are needed (e.g., cred expiry warning)

  // --- Configuration Properties ---
  @Value("${security.account.lock.duration-minutes:15}")
  private long lockDurationMinutes;

  @Value("${security.account.credentials.expire-days:90}")
  private long credentialsExpireDays;

  @Value("${security.account.inactivity.expire-days:180}")
  private long inactivityExpireDays;

  /**
   * Scheduled task to automatically unlock user accounts whose lock duration has expired.
   * Runs based on the cron expression defined in {@code iam.scheduler.unlock.cron}.
   * Skips execution if {@code lockDurationMinutes} is non-positive.
   */
  @Scheduled(cron = "${iam.scheduler.unlock.cron:0 */15 * * * *}") // Default: Every 15 minutes
  @Transactional // Ensures finding locked users and unlocking them is atomic for this run
  public void unlockExpiredLockedAccounts() {
    // Check if locking mechanism duration is configured
    if (lockDurationMinutes <= 0) {
      log.trace("[Scheduler - Unlock] Account unlocking based on duration is disabled (lockDurationMinutes <= 0).");
      return;
    }

    // Calculate the time threshold based on lock duration
    Instant unlockThreshold = Instant.now().minus(Duration.ofMinutes(lockDurationMinutes));
    log.debug("[Scheduler - Unlock] Checking for accounts locked on or before: {}", unlockThreshold);

    // Find users who are locked and whose lock time is at or before the threshold
    // Note: The query in UserRepository uses <= now, which might be slightly different if run exactly on the minute.
    // Adjusting query or threshold logic might be needed for exactness. Using <= now is generally safe.
    List<User> usersToUnlock = userRepository.findLockedUsersWithExpiredLockTime(Instant.now());

    if (!usersToUnlock.isEmpty()) {
      log.info("[Scheduler - Unlock] Found {} user account(s) eligible for automatic unlock.", usersToUnlock.size());
      for (User user : usersToUnlock) {
        UUID userId = user.getId();
        String username = user.getUsername();
        UUID orgId = (user.getOrganization() != null) ? user.getOrganization().getId() : null;
        try {
          // Use the specific repository method to unlock
          userRepository.unlockAccount(userId); // Resets lock flag, lock time, and attempts
          log.info("[Scheduler - Unlock] Automatically unlocked user account '{}' (ID: {})", username, userId);

          // Log audit event
          auditEventService.logEvent(AuditEventType.ACCOUNT_UNLOCKED,
                  String.format("User account '%s' automatically unlocked by scheduler", username),
                  SYSTEM_ACTOR, "SUCCESS",
                  "USER", userId.toString(), orgId, // Target user
                  "Lock time expired"); // Details
        } catch (Exception e) {
          // Log error but continue processing other users
          log.error("[Scheduler - Unlock] Failed to unlock user account '{}' (ID: {}): {}", username, userId, e.getMessage(), e);
        }
      }
      log.info("[Scheduler - Unlock] Finished processing {} unlockable account(s).", usersToUnlock.size());
    } else {
      log.debug("[Scheduler - Unlock] No locked accounts found with expired lock times.");
    }
  }

  /**
   * Scheduled task to mark user credentials (passwords) as expired based on their age.
   * Runs based on the cron expression defined in {@code iam.scheduler.credentials-expire.cron}.
   * Skips execution if {@code credentialsExpireDays} is non-positive.
   */
  @Scheduled(cron = "${iam.scheduler.credentials-expire.cron:0 0 1 * * *}") // Default: Daily at 1 AM
  @Transactional
  public void expireOldCredentials() {
    if (credentialsExpireDays <= 0) {
      log.trace("[Scheduler - CredExpire] Credential expiration check is disabled (credentialsExpireDays <= 0).");
      return;
    }

    // Calculate the date threshold for expiration
    Instant expirationThresholdDate = Instant.now().minus(Duration.ofDays(credentialsExpireDays));
    log.debug("[Scheduler - CredExpire] Checking for credentials last changed before: {}", expirationThresholdDate);

    // Find users whose credentials are not expired but password changed before threshold
    List<User> usersToExpire = userRepository.findUsersWithExpiringCredentials(expirationThresholdDate);

    if (!usersToExpire.isEmpty()) {
      log.info("[Scheduler - CredExpire] Found {} user account(s) with credentials to expire.", usersToExpire.size());
      for (User user : usersToExpire) {
        UUID userId = user.getId();
        String username = user.getUsername();
        UUID orgId = (user.getOrganization() != null) ? user.getOrganization().getId() : null;
        try {
          // Use repository method to update the status
          userRepository.updateCredentialsExpiredStatus(userId, false); // Mark as expired
          log.info("[Scheduler - CredExpire] Marked credentials as expired for user '{}' (ID: {})", username, userId);

          // Log audit event
          auditEventService.logEvent(AuditEventType.CREDENTIALS_EXPIRED,
                  String.format("User credentials for '%s' marked as expired by scheduler", username),
                  SYSTEM_ACTOR, "SUCCESS",
                  "USER", userId.toString(), orgId, // Target user
                  "Password changed date: " + user.getPasswordChangedDate()); // Details

//           Optional: Send notification to user about password expiration
//           if (notificationService != null) {
//               notificationService.sendPasswordExpiredNotification(user);
//           }

        } catch (Exception e) {
          log.error("[Scheduler - CredExpire] Failed to expire credentials for user '{}' (ID: {}): {}", username, userId, e.getMessage(), e);
        }
      }
      log.info("[Scheduler - CredExpire] Finished processing {} credential expiration(s).", usersToExpire.size());
    } else {
      log.debug("[Scheduler - CredExpire] No users found with credentials needing expiration.");
    }
  }

  /**
   * Scheduled task to disable user accounts that have been inactive for a configured period.
   * Runs based on the cron expression defined in {@code iam.scheduler.inactivity-disable.cron}.
   * Skips execution if {@code inactivityExpireDays} is non-positive.
   * Excludes users belonging to the Super Organization.
   */
  @Scheduled(cron = "${iam.scheduler.inactivity-disable.cron:0 0 2 * * *}") // Default: Daily at 2 AM
  @Transactional
  public void disableInactiveUsers() {
    if (inactivityExpireDays <= 0) {
      log.trace("[Scheduler - Inactivity] Inactivity check is disabled (inactivityExpireDays <= 0).");
      return;
    }

    // Calculate the inactivity threshold date
    Instant inactivityThreshold = Instant.now().minus(Duration.ofDays(inactivityExpireDays));
    log.debug("[Scheduler - Inactivity] Checking for users inactive since: {}", inactivityThreshold);

    // Find enabled, non-Super Org users whose last login is null or before the threshold
    List<User> usersToDisable = userRepository.findUsersForInactivityCheck(inactivityThreshold);

    if (!usersToDisable.isEmpty()) {
      log.info("[Scheduler - Inactivity] Found {} potentially inactive user account(s) to disable.", usersToDisable.size());
      for (User user : usersToDisable) {
        UUID userId = user.getId();
        String username = user.getUsername();
        UUID orgId = user.getOrganization().getId(); // Org is non-null due to query filter
        try {
          // Use repository method to disable the user
          userRepository.disableUser(userId); // Sets enabled = false
          log.info("[Scheduler - Inactivity] Disabled inactive user account '{}' (ID: {})", username, userId);

          // Log audit event
          auditEventService.logEvent(AuditEventType.ACCOUNT_INACTIVITY_DISABLED,
                  String.format("User account '%s' disabled due to inactivity by scheduler", username),
                  SYSTEM_ACTOR, "SUCCESS",
                  "USER", userId.toString(), orgId, // Target user
                  "Last login: " + (user.getLastLoginDate() != null ? user.getLastLoginDate() : "Never")); // Details

          // Optional: Send notification to user (or admin) about account disabling
          // if (notificationService != null) {
          //     notificationService.sendAccountDisabledNotification(user, "Inactivity");
          // }

        } catch (Exception e) {
          log.error("[Scheduler - Inactivity] Failed to disable inactive user '{}' (ID: {}): {}", username, userId, e.getMessage(), e);
        }
      }
      log.info("[Scheduler - Inactivity] Finished processing {} inactivity disable action(s).", usersToDisable.size());
    } else {
      log.debug("[Scheduler - Inactivity] No inactive users found requiring disabling.");
    }
  }

  /**
   * Scheduled task to clean up expired verification and password reset tokens from the database.
   * Runs based on the cron expression defined in {@code iam.scheduler.token-cleanup.cron}.
   */
  @Scheduled(cron = "${iam.scheduler.token-cleanup.cron:0 0 3 * * *}") // Default: Daily at 3 AM
  @Transactional
  public void cleanupExpiredTokens() {
    Instant now = Instant.now();
    log.debug("[Scheduler - TokenCleanup] Cleaning up verification tokens expired on or before: {}", now);
    try {
      // Use repository method to delete expired tokens directly
      int deletedCount = tokenRepository.deleteAllExpiredSince(now);
      if (deletedCount > 0) {
        log.info("[Scheduler - TokenCleanup] Successfully deleted {} expired verification token(s).", deletedCount);
        // Optional: Log a system audit event for the cleanup action itself
        // auditEventService.logEvent(AuditEventType.SYSTEM_MAINTENANCE, "Expired token cleanup ran", SYSTEM_ACTOR, "SUCCESS", null, null, null, "Deleted count: " + deletedCount);
      } else {
        log.debug("[Scheduler - TokenCleanup] No expired verification tokens found to delete.");
      }
    } catch (Exception e) {
      // Log errors during cleanup, but don't let it stop other scheduler tasks
      log.error("[Scheduler - TokenCleanup] Error occurred during expired token cleanup: {}", e.getMessage(), e);
    }
  }
}