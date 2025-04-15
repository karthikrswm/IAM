// File: src/main/java/org/example/iam/audit/Auditable.java
package org.example.iam.audit;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
// Removed jakarta.persistence.Temporal and TemporalType as they are not needed for java.time types
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant; // Use java.time.Instant for timestamps

/**
 * Abstract base class for JPA entities requiring auditing information.
 * <p>
 * Entities extending this class will automatically have fields populated for:
 * <ul>
 * <li>{@code createdBy}: The identifier of the principal who created the entity.</li>
 * <li>{@code createdDate}: The timestamp when the entity was created.</li>
 * <li>{@code lastModifiedBy}: The identifier of the principal who last modified the entity.</li>
 * <li>{@code lastModifiedDate}: The timestamp when the entity was last modified.</li>
 * </ul>
 * Population is handled by Spring Data JPA's auditing mechanism, specifically the
 * {@link AuditingEntityListener}, which leverages an {@link org.springframework.data.domain.AuditorAware}
 * bean (like {@link AuditorAwareImpl}) to determine the current principal.
 * </p>
 * <p>
 * Timestamps are stored using {@link Instant} for better precision and time zone handling.
 * The auditor type {@code <U>} is typically {@link String} representing a username or system ID.
 * </p>
 *
 * @param <U> the type of the auditor identifier (e.g., String).
 */
@Getter
@Setter
@MappedSuperclass // Designates this as a base class whose fields are mapped to inheriting entities' tables.
@EntityListeners(AuditingEntityListener.class) // Enables JPA auditing features for entities extending this class.
public abstract class Auditable<U> {

  /**
   * The identifier of the principal that created this entity.
   * Automatically populated on creation. Cannot be updated.
   */
  @CreatedBy
  @Column(name = "created_by", nullable = false, updatable = false, length = 50) // Adjust length as needed
  protected U createdBy;

  /**
   * The timestamp when this entity was first persisted.
   * Automatically populated on creation. Cannot be updated. Uses UTC.
   */
  @CreatedDate
  @Column(name = "created_date", nullable = false, updatable = false)
  // @Temporal(TIMESTAMP) // Not needed for java.time.Instant with modern JPA providers
  protected Instant createdDate; // Use Instant for timestamp

  /**
   * The identifier of the principal that last modified this entity.
   * Automatically populated on creation and update.
   */
  @LastModifiedBy
  @Column(name = "last_modified_by", length = 50) // Adjust length as needed
  protected U lastModifiedBy;

  /**
   * The timestamp when this entity was last modified.
   * Automatically populated on creation and update. Uses UTC.
   */
  @LastModifiedDate
  @Column(name = "last_modified_date", nullable = false)
  // @Temporal(TIMESTAMP) // Not needed for java.time.Instant
  protected Instant lastModifiedDate; // Use Instant for timestamp
}