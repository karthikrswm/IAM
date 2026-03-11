// File: src/main/java/org/example/iam/repository/AuditEventRepository.java
package org.example.iam.repository;

import org.example.iam.entity.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation; // Correct import for Propagation
import org.springframework.transaction.annotation.Transactional; // Correct import for Transactional

import java.util.List;
// Removed unused UUID import

/**
 * Spring Data JPA repository interface for the {@link AuditEvent} entity.
 * Provides standard CRUD operations and custom methods for querying audit events,
 * particularly for the Kafka publishing scheduler.
 */
@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> { // Primary key type is Long

  /**
   * Finds a page of {@link AuditEvent} entities where the {@code publishedToKafka} flag is false,
   * ordered by their primary key (database ID) in ascending order.
   * <p>
   * This method is used by the {@link org.example.iam.service.AuditEventScheduler} to retrieve
   * batches of unpublished events for sending to Kafka. Ordering by ID provides a reasonable
   * approximation of chronological order for processing.
   * </p>
   *
   * @param pageable Pagination information (page number, size).
   * @return A {@link Page} containing unpublished AuditEvent entities.
   */
  Page<AuditEvent> findByPublishedToKafkaFalseOrderByIdAsc(Pageable pageable);

  /**
   * Marks a list of audit events (identified by their database IDs) as published to Kafka
   * by setting their {@code publishedToKafka} flag to true.
   * <p>
   * This is an {@link Modifying @Modifying} query, indicating it changes data.
   * It requires {@link Transactional @Transactional} support. The propagation level is set
   * to {@link Propagation#MANDATORY MANDATORY} to ensure this method is always called within
   * an existing transaction (typically the one started by the calling scheduler method),
   * guaranteeing atomicity between fetching events and marking them as published.
   * </p>
   *
   * @param ids A list of database primary keys (Long IDs) of the audit events to mark as published.
   * @return The number of rows updated in the database.
   */
  @Modifying // Indicates a query that modifies data
  @Transactional(propagation = Propagation.MANDATORY) // Must run within an existing transaction
  @Query("UPDATE AuditEvent ae SET ae.publishedToKafka = true WHERE ae.id IN :ids")
  int markAsPublished(@Param("ids") List<Long> ids);

  // Additional query methods can be added here if needed for searching/filtering audit logs, e.g.:
  // Page<AuditEvent> findByActorIgnoreCase(String actor, Pageable pageable);
  // Page<AuditEvent> findByEventTypeAndEventTimestampBetween(String eventType, Instant start, Instant end, Pageable pageable);
  // Page<AuditEvent> findByOrganizationId(UUID organizationId, Pageable pageable);

}