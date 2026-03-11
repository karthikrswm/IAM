// File: src/main/java/org/example/iam/service/AuditEventService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.AuditEventType; // Enum defining event types
import org.example.iam.entity.AuditEvent;
import org.example.iam.repository.AuditEventRepository; // Repository for persistence
import org.springframework.scheduling.annotation.Async; // For async execution
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional; // For transaction management

import java.util.UUID;

/**
 * Service responsible for creating and persisting audit event logs.
 * <p>
 * Provides methods to log various system actions and events. Logging is performed
 * asynchronously ({@link Async @Async}) to minimize performance impact on the calling operation.
 * </p>
 * <p>
 * Persistence uses {@link Propagation#REQUIRES_NEW REQUIRES_NEW} transaction propagation.
 * This ensures that the audit log record is saved in its own transaction, separate from
 * the main business operation's transaction. Consequently, audit logs are persisted
 * even if the primary operation fails and its transaction rolls back.
 * </p>
 */
@Service
@RequiredArgsConstructor // Lombok generates constructor for final fields
@Slf4j
public class AuditEventService {

  private final AuditEventRepository auditEventRepository;
  // Note: Does not directly depend on AuditorAware. The 'actor' should be explicitly
  // passed by the calling service, as the context might be 'SYSTEM', 'ANONYMOUS',
  // or a specific user identifier relevant to the action being audited.

  /**
   * Core method to log an audit event asynchronously and in a new transaction.
   *
   * @param eventType          The type of the event (enum). Must not be null.
   * @param description        A human-readable description of the event.
   * @param actor              The identifier of the user or system performing the action (e.g., username, "SYSTEM", "ANONYMOUS"). Can be null if context unknown.
   * @param status             The outcome status ("SUCCESS" or "FAILURE"). Must not be null.
   * @param targetResourceType (Optional) Type of the main resource affected (e.g., "USER", "ORGANIZATION").
   * @param targetResourceId   (Optional) ID (usually UUID as String) of the main resource affected.
   * @param organizationId     (Optional) UUID of the organization context for the event.
   * @param details            (Optional) Additional contextual details, often stored as JSON string or descriptive text.
   */
  @Async("taskExecutor") // Execute this method asynchronously using the configured task executor
  @Transactional(propagation = Propagation.REQUIRES_NEW) // Run in a separate, independent transaction
  public void logEvent(AuditEventType eventType, String description, String actor, String status,
                       String targetResourceType, String targetResourceId, UUID organizationId, String details) {

    // Basic validation for essential fields
    if (eventType == null) {
      log.error("Audit event logging failed: EventType cannot be null. Description: '{}', Actor: '{}', Status: '{}'",
              description, actor, status);
      return; // Do not proceed if type is missing
    }
    if (status == null) {
      log.error("Audit event logging failed: Status cannot be null. Type: {}, Description: '{}', Actor: '{}'",
              eventType, description, actor);
      return; // Do not proceed if status is missing
    }

    try {
      AuditEvent event = AuditEvent.builder()
              .eventType(eventType.name()) // Store enum name as string
              .description(description)
              .actor(actor) // Actor provided by the calling service context
              .status(status) // e.g., "SUCCESS", "FAILURE"
              .targetResourceType(targetResourceType)
              .targetResourceId(targetResourceId)
              .organizationId(organizationId)
              .details(details)
              // eventTimestamp is set automatically by @CreationTimestamp
              // eventId is set automatically by database default/generation strategy
              // publishedToKafka defaults to false via @Builder.Default
              .build();

      AuditEvent savedEvent = auditEventRepository.save(event);
      // Log minimal info on successful save at TRACE level to avoid excessive logging from the logger itself
      log.trace("Audit event persisted: DB_ID={}, EventID={}, Type={}, Actor={}, Status={}",
              savedEvent.getId(), savedEvent.getEventId(), eventType, actor, status);

    } catch (Exception e) {
      // Log persistence errors robustly but DO NOT re-throw.
      // We want the audit log failure NOT to cause the primary business operation to fail.
      // Errors here indicate issues with the audit logging subsystem itself (DB connection, schema issues, etc.).
      log.error("!!! Failed to persist audit event: Type={}, Actor={}, Desc='{}', Status={}. Error: {} !!!",
              eventType, actor, description, status, e.getMessage(), e);
      // TODO: Implement fallback logging (e.g., to a file) or alerting for critical audit failures.
    }
  }

  // --- Convenience Overloads for Common Scenarios ---
  // These overloads default the status to "SUCCESS" and provide simpler signatures.

  /**
   * Convenience method to log a simple success event with type, description, and actor.
   *
   * @param eventType   The type of event.
   * @param description A description of the event.
   * @param actor       The identifier of the actor.
   */
  public void logEvent(AuditEventType eventType, String description, String actor) {
    logEvent(eventType, description, actor, "SUCCESS", null, null, null, null);
  }

  /**
   * Convenience method to log a success event associated with a specific organization.
   *
   * @param eventType      The type of event.
   * @param description    A description of the event.
   * @param actor          The identifier of the actor.
   * @param organizationId The UUID of the relevant organization.
   */
  public void logEvent(AuditEventType eventType, String description, String actor, UUID organizationId) {
    logEvent(eventType, description, actor, "SUCCESS", null, null, organizationId, null);
  }

  /**
   * Convenience method to log a success event targeting a specific resource within an organization.
   *
   * @param eventType          The type of event.
   * @param description        A description of the event.
   * @param actor              The identifier of the actor.
   * @param targetResourceType The type of the target resource.
   * @param targetResourceId   The ID of the target resource.
   * @param organizationId     The UUID of the relevant organization.
   */
  public void logEvent(AuditEventType eventType, String description, String actor,
                       String targetResourceType, String targetResourceId, UUID organizationId) {
    logEvent(eventType, description, actor, "SUCCESS", targetResourceType, targetResourceId, organizationId, null);
  }

  /**
   * Convenience method to log a failure event, including details.
   *
   * @param eventType          The type of event.
   * @param description        A description of the failure.
   * @param actor              The identifier of the actor attempting the action.
   * @param targetResourceType (Optional) The type of the target resource.
   * @param targetResourceId   (Optional) The ID of the target resource.
   * @param organizationId     (Optional) The UUID of the relevant organization.
   * @param details            Details about the failure (e.g., error message, stack trace snippet).
   */
  public void logFailureEvent(AuditEventType eventType, String description, String actor,
                              String targetResourceType, String targetResourceId, UUID organizationId, String details) {
    logEvent(eventType, description, actor, "FAILURE", targetResourceType, targetResourceId, organizationId, details);
  }

  /**
   * Convenience method to log a simple failure event with description, actor, and details.
   *
   * @param eventType   The type of event.
   * @param description A description of the failure.
   * @param actor       The identifier of the actor attempting the action.
   * @param details     Details about the failure.
   */
  public void logFailureEvent(AuditEventType eventType, String description, String actor, String details) {
    logEvent(eventType, description, actor, "FAILURE", null, null, null, details);
  }

}