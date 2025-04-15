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
import org.springframework.web.util.UriComponentsBuilder; // For building URLs

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
    messageBody.append(String.format("This link is valid for %d minutes.\n\n", 1440)); // TODO: Make duration configurable if needed

    if (temporaryPassword != null) {
      // --- SECURITY WARNING ---
      // Including temporary passwords in email is insecure.
      // Production systems should ideally guide the user through a forced password reset
      // immediately after email verification instead of sending a password directly.
      // Consider removing this section or making it conditional based on security policy.
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
    // Frontend app at this URL should handle the token and call the /api/v1/auth/reset-password endpoint
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

            This link is valid for %d minutes.

            If you did not request a password reset, please ignore this email or contact support if you have concerns.

            Regards,
            The IAM Team
            """,
            user.getUsername(),
            resetUrl,
            60 // TODO: Make duration configurable if needed
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
    // TODO: Make lock duration configurable and potentially include in email
    String messageBody = String.format(
            """
            Hello %s,

            Your IAM service account associated with this email address was temporarily locked
            due to multiple unsuccessful login attempts.

            The lock will typically expire automatically after a short period.
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