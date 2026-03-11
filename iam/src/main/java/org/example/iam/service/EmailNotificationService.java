// File: src/main/java/org/example/iam/service/EmailNotificationService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async; // For sending emails asynchronously
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils; // <<< ADDED import
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder; // For building URLs

import java.util.List; // <<< ADDED import

/**
 * Service implementation for sending email notifications using Spring Mail.
 * Implements the {@link NotificationService} interface.
 * <p>
 * Emails are sent asynchronously using the configured {@code taskExecutor} bean
 * to avoid blocking the main application threads.
 * </p>
 * <p>
 * Reads configuration like sender address and base URL from application properties.
 * Handles potential {@link MailException} errors during sending and logs them.
 * </p>
 */
@Service
@RequiredArgsConstructor // Creates constructor for final fields (mailSender)
@Slf4j
public class EmailNotificationService implements NotificationService {

  private final JavaMailSender mailSender;

  // Email sender address from application properties
  @Value("${iam.support.email:noreply@example.local}") // Provide a default value
  private String fromEmailAddress;

  // Base URL for constructing links in emails (verification, password reset)
  @Value("${iam.base.url:http://localhost:8080}") // Default for local dev
  private String applicationBaseUrl;

  // Expiry warning days (used for email text)
  @Value("${security.account.credentials.warn-days:14}")
  private int passwordWarnDays;

  /**
   * Sends an email verification notification asynchronously.
   * Includes a verification link and potentially a temporary password.
   * **Security Warning:** Sending temporary passwords via email is generally insecure.
   *
   * @param user              The user to notify.
   * @param verificationToken The verification token string.
   * @param temporaryPassword The temporary password (if applicable, handle securely!). Null if not applicable.
   */
  @Async("taskExecutor") // Specify the async executor bean name
  @Override
  public void sendVerificationEmail(User user, String verificationToken, String temporaryPassword) {
    if (user == null || user.getPrimaryEmail() == null) {
      log.error("Cannot send verification email: User or primary email is null.");
      return;
    }

    String recipientAddress = user.getPrimaryEmail();
    String subject = "Verify Your Email Address - IAM Service";

    // Construct the verification URL using the base URL and token
    String verificationUrl = UriComponentsBuilder.fromHttpUrl(applicationBaseUrl)
            .path("/api/v1/auth/verify-email") // Path to the verification endpoint
            .queryParam("token", verificationToken)
            .build() // Build the components
            .toUriString(); // Get the full URL string

    // Construct email body
    StringBuilder messageBody = new StringBuilder();
    messageBody.append(String.format("Hello %s,\n\n", user.getUsername()));
    messageBody.append("Thank you for registering. Please verify your email address by clicking the link below:\n");
    messageBody.append(verificationUrl).append("\n\n");
    messageBody.append("This link is valid for 24 hours.\n\n"); // Hardcoded for now, could be property

    if (temporaryPassword != null) {
      log.warn("Including insecure temporary password in verification email for user '{}'.", user.getUsername());
      messageBody.append("----------------------------------------\n");
      messageBody.append("Your temporary password is: ").append(temporaryPassword).append("\n");
      messageBody.append("You MUST change this password immediately after verifying your email and logging in.\n");
      messageBody.append("----------------------------------------\n\n");
    }

    messageBody.append("If you did not request this verification, please ignore this email.\n\n");
    messageBody.append("Regards,\nThe IAM Team");

    log.info("Attempting to send verification email to '{}' for user '{}'.", recipientAddress, user.getUsername());
    sendEmail(recipientAddress, subject, messageBody.toString());
  }

  /**
   * Sends a password reset link email asynchronously.
   *
   * @param user       The user requesting the reset.
   * @param resetToken The password reset token string.
   */
  @Async("taskExecutor")
  @Override
  public void sendPasswordResetEmail(User user, String resetToken) {
    if (user == null || user.getPrimaryEmail() == null) {
      log.error("Cannot send password reset email: User or primary email is null.");
      return;
    }

    String recipientAddress = user.getPrimaryEmail();
    String subject = "Password Reset Request - IAM Service";

    // Construct the password reset URL (points to frontend path usually)
    String resetUrl = UriComponentsBuilder.fromHttpUrl(applicationBaseUrl) // Use base URL (might be frontend URL in reality)
            .path("/reset-password") // Example frontend path
            .queryParam("token", resetToken)
            .build()
            .toUriString();

    String messageBody = String.format(
            """
            Hello %s,

            We received a request to reset your password for the IAM service.
            Click the link below to set a new password:
            %s

            This link is valid for 60 minutes.

            If you did not request a password reset, please ignore this email or contact support if you have concerns.

            Regards,
            The IAM Team
            """,
            user.getUsername(),
            resetUrl
    );

    log.info("Attempting to send password reset email to '{}' for user '{}'.", recipientAddress, user.getUsername());
    sendEmail(recipientAddress, subject, messageBody);
  }

  /**
   * Sends a confirmation email after a successful password change asynchronously.
   *
   * @param user The user whose password was changed.
   */
  @Async("taskExecutor")
  @Override
  public void sendPasswordChangeConfirmationEmail(User user) {
    if (user == null || user.getPrimaryEmail() == null) {
      log.error("Cannot send password change confirmation: User or primary email is null.");
      return;
    }

    String recipientAddress = user.getPrimaryEmail();
    String subject = "Your Password Has Been Changed - IAM Service";
    String messageBody = String.format(
            """
            Hello %s,

            This email confirms that the password for your IAM service account was successfully changed recently.

            If you did not make this change, please contact support immediately to secure your account.

            Regards,
            The IAM Team
            """,
            user.getUsername()
    );

    log.info("Attempting to send password change confirmation email to '{}' for user '{}'.", recipientAddress, user.getUsername());
    sendEmail(recipientAddress, subject, messageBody);
  }

  /**
   * Sends a notification email informing the user their account has been locked asynchronously.
   *
   * @param user The user whose account was locked.
   */
  @Async("taskExecutor")
  @Override
  public void sendAccountLockedEmail(User user) {
    if (user == null || user.getPrimaryEmail() == null) {
      log.error("Cannot send account locked email: User or primary email is null.");
      return;
    }

    String recipientAddress = user.getPrimaryEmail();
    String subject = "Your Account Has Been Locked - IAM Service";
    String messageBody = String.format(
            """
            Hello %s,

            Your IAM service account associated with this email address was temporarily locked
            due to multiple unsuccessful login attempts.

            The lock will typically expire automatically after a short period (if configured).
            If you continue to experience issues, please try resetting your password or contact support.

            Regards,
            The IAM Team
            """,
            user.getUsername()
    );

    log.info("Attempting to send account locked notification email to '{}' for user '{}'.", recipientAddress, user.getUsername());
    sendEmail(recipientAddress, subject, messageBody);
  }

  /**
   * Sends a warning notification to the user that their password will expire soon.
   *
   * @param user            The user whose password is about to expire.
   * @param daysUntilExpiry The number of days remaining until the password expires.
   */
  @Async("taskExecutor") // <<< ADDED Implementation
  @Override
  public void sendPasswordExpiryWarningEmail(User user, long daysUntilExpiry) {
    if (user == null || user.getPrimaryEmail() == null) {
      log.error("Cannot send password expiry warning email: User or primary email is null.");
      return;
    }

    String recipientAddress = user.getPrimaryEmail();
    String subject = "Password Expiry Warning - IAM Service";
    String messageBody = String.format(
            """
            Hello %s,

            This is a reminder that your password for the IAM service account will expire in %d day(s).

            Please change your password before it expires to avoid any interruption in service.
            You can change your password through your profile settings.

            If you have already changed your password recently, please disregard this message.

            Regards,
            The IAM Team
            """,
            user.getUsername(),
            daysUntilExpiry
    );

    log.info("Attempting to send password expiry warning email to '{}' for user '{}' ({} days remaining).",
            recipientAddress, user.getUsername(), daysUntilExpiry);
    sendEmail(recipientAddress, subject, messageBody);
  }

  /**
   * Sends a notification to the user that their password has expired.
   *
   * @param user The user whose password has expired.
   */
  @Async("taskExecutor") // <<< ADDED Implementation
  @Override
  public void sendPasswordExpiredEmail(User user) {
    if (user == null || user.getPrimaryEmail() == null) {
      log.error("Cannot send password expired email: User or primary email is null.");
      return;
    }

    String recipientAddress = user.getPrimaryEmail();
    String subject = "Your Password Has Expired - IAM Service";
    String messageBody = String.format(
            """
            Hello %s,

            Your password for the IAM service account has expired.

            You will need to reset your password to regain access to your account.
            Please follow the password reset procedure or contact your administrator.

            Regards,
            The IAM Team
            """,
            user.getUsername()
    );

    log.info("Attempting to send password expired email to '{}' for user '{}'.",
            recipientAddress, user.getUsername());
    sendEmail(recipientAddress, subject, messageBody);
  }

  /**
   * Sends a notification to the administrators of an organization that a user's password has expired.
   *
   * @param expiredUser The user whose password has expired.
   * @param orgAdmins   A list of User entities representing the administrators of the organization.
   */
  @Async("taskExecutor") // <<< ADDED Implementation
  @Override
  public void sendAdminPasswordExpiredNotification(User expiredUser, List<User> orgAdmins) {
    if (expiredUser == null || CollectionUtils.isEmpty(orgAdmins)) {
      log.warn("Cannot send admin password expired notification: Expired user is null or no admins found.");
      return;
    }

    String subject = String.format("User Password Expired Notification - %s", expiredUser.getUsername());
    String messageBody = String.format(
            """
            Hello Administrator,

            This notification is to inform you that the password for the following user in your organization has expired:

            Username: %s
            Primary Email: %s
            Organization: %s

            The user will be required to reset their password upon their next login attempt (if applicable) or via the standard password reset flow.

            Regards,
            IAM System Monitoring
            """,
            expiredUser.getUsername(),
            expiredUser.getPrimaryEmail(),
            expiredUser.getOrganization() != null ? expiredUser.getOrganization().getOrgName() : "N/A"
    );

    for (User admin : orgAdmins) {
      if (admin != null && StringUtils.hasText(admin.getPrimaryEmail())) {
        log.info("Attempting to send password expired notification for user '{}' to admin '{}' at '{}'.",
                expiredUser.getUsername(), admin.getUsername(), admin.getPrimaryEmail());
        sendEmail(admin.getPrimaryEmail(), subject, messageBody);
      } else {
        log.warn("Skipping admin notification for expired user '{}': Admin user object or primary email is invalid: {}",
                expiredUser.getUsername(), admin);
      }
    }
  }


  /**
   * Private helper method to actually send the email using JavaMailSender.
   * Includes basic error handling and logging.
   *
   * @param to      Recipient email address.
   * @param subject Email subject line.
   * @param text    Email body content.
   */
  private void sendEmail(String to, String subject, String text) {
    try {
      SimpleMailMessage message = new SimpleMailMessage();
      message.setFrom(fromEmailAddress); // Set sender from configured property
      message.setTo(to);
      message.setSubject(subject);
      message.setText(text);

      mailSender.send(message);
      log.debug("Email sent successfully to '{}' with subject '{}'.", to, subject); // Debug level for success

    } catch (MailException e) {
      // Log specific mail exceptions (e.g., connection refused, auth failed)
      log.error("MailException sending email to '{}' with subject '{}': {}", to, subject, e.getMessage(), e);
      // TODO: Implement monitoring/alerting/retry logic for failed emails based on requirements
    } catch (Exception e) {
      // Catch any other unexpected exceptions during sending
      log.error("Unexpected error sending email to '{}' with subject '{}': {}", to, subject, e.getMessage(), e);
    }
  }
}