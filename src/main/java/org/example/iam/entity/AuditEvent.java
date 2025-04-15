// File: src/main/java/org/example/iam/entity/AuditEvent.java
package org.example.iam.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.iam.constant.AuditEventType; // Context for eventType field
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a persisted audit log entry recording significant actions or events
 * within the IAM system.
 * <p>
 * These events are typically logged asynchronously and stored for security analysis,
 * compliance, and operational monitoring. They may also be published to an
 * external system (like Kafka) for further processing.
 * </p>
 */
@Entity
@Table(name = "audit_events", indexes = {
        // Indexes for common query patterns
        @Index(name = "idx_audit_event_type", columnList = "event_type"),
        @Index(name = "idx_audit_event_timestamp", columnList = "event_timestamp"),
        @Index(name = "idx_audit_actor", columnList = "actor"),
        @Index(name = "idx_audit_target_resource", columnList = "target_resource_type, target_resource_id"),
        @Index(name = "idx_audit_organization_id", columnList = "organization_id"),
        @Index(name = "idx_audit_published_status", columnList = "published_to_kafka") // For scheduler query
})
@Getter
@Setter
@NoArgsConstructor // Required by JPA
@AllArgsConstructor // Useful for @Builder
@Builder(toBuilder = true) // Allows creating copies and modifying with builder
// Note: AuditEvent does not extend Auditable itself, as it *is* the audit record.
public class AuditEvent {

  /**
   * Primary key for the audit event record (auto-incrementing long).
   */
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  /**
   * A unique identifier (UUID) for this specific event instance.
   * Generated automatically by the database upon insertion.
   */
  @Column(name = "event_id", nullable = false, unique = true, updatable = false,
          columnDefinition = "BINARY(16) DEFAULT (UUID_TO_BIN(UUID()))") // MySQL function for default UUID
  @Builder.Default  // Inform JPA about UUID generation strategy
  private UUID eventId = UUID.randomUUID();

  /**
   * The type of event that occurred, corresponding to {@link AuditEventType}.
   * Stored as a string representation of the enum name.
   */
  @Column(name = "event_type", nullable = false, length = 50)
  private String eventType;

  /**
   * A detailed, human-readable description of the event.
   */
  @Lob // Suitable for potentially long descriptions
  @Column(name = "description", columnDefinition = "TEXT") // Use TEXT for long descriptions
  @JdbcTypeCode(SqlTypes.LONGVARCHAR) // Map to appropriate JDBC type
  private String description;

  /**
   * The identifier (e.g., username, system identifier) of the principal that initiated the event.
   * Can be SYSTEM, ANONYMOUS, or a user identifier.
   */
  @Column(name = "actor", length = 50, nullable = true) // Actor might be null in some edge cases
  private String actor;

  /**
   * The type of the main resource targeted by the event (e.g., "USER", "ORGANIZATION").
   * Optional, may not apply to all event types.
   */
  @Column(name = "target_resource_type", length = 50, nullable = true)
  private String targetResourceType;

  /**
   * The identifier (usually a String representation of a UUID or other ID) of the target resource.
   * Optional, may not apply to all event types.
   */
  @Column(name = "target_resource_id", length = 50, nullable = true) // Adjust length if needed
  private String targetResourceId;

  /**
   * The identifier (UUID) of the organization associated with this event context, if applicable.
   * Useful for filtering audit logs by tenant.
   */
  @Column(name = "organization_id", columnDefinition = "BINARY(16)", nullable = true)
  private UUID organizationId;

  /**
   * The exact time when the event occurred (or was logged).
   * Automatically set upon creation. Uses UTC.
   */
  @CreationTimestamp // Automatically set by Hibernate on creation
  @Column(name = "event_timestamp", nullable = false, updatable = false)
  private Instant eventTimestamp;

  /**
   * The outcome status of the logged action (e.g., "SUCCESS", "FAILURE").
   * Defaults to "SUCCESS".
   */
  @Column(name = "status", length = 10, nullable = false)
  @Builder.Default // Set default value via builder
  private String status = "SUCCESS";

  /**
   * Additional contextual details related to the event. Can store structured data (like JSON)
   * or supplementary information.
   */
  @Lob // Suitable for potentially large detail strings (e.g., JSON)
  @Column(name = "details", columnDefinition = "TEXT")
  @JdbcTypeCode(SqlTypes.LONGVARCHAR)
  private String details;

  /**
   * Flag indicating whether this audit event has been successfully published to the
   * configured Kafka topic by the {@link org.example.iam.service.AuditEventScheduler}.
   * Defaults to false.
   */
  @Column(name = "published_to_kafka", nullable = false)
  @Builder.Default // Default new events to unpublished
  private boolean publishedToKafka = false;

  /**
   * Provides a concise string representation of the AuditEvent, useful for logging.
   * Excludes potentially large 'details' and 'description' fields.
   *
   * @return A string representation of the audit event.
   */
  @Override
  public String toString() {
    return "AuditEvent{" +
            "id=" + id +
            ", eventId=" + eventId +
            ", eventTimestamp=" + eventTimestamp +
            ", eventType='" + eventType + '\'' +
            ", actor='" + actor + '\'' +
            ", status='" + status + '\'' +
            ", publishedToKafka=" + publishedToKafka + // Included status flag
            ", targetResourceType='" + targetResourceType + '\'' +
            ", targetResourceId='" + targetResourceId + '\'' +
            ", organizationId=" + organizationId +
            '}';
  }
}