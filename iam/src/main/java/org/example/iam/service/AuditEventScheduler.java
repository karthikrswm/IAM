// File: src/main/java/org/example/iam/service/AuditEventScheduler.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.dto.AuditEventDto; // DTO for Kafka message
import org.example.iam.entity.AuditEvent;
import org.example.iam.repository.AuditEventRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional; // For atomic read-update
import org.springframework.util.CollectionUtils; // For checking empty collections

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Scheduled task responsible for periodically publishing audit events stored in the
 * database to a Kafka topic.
 * <p>
 * This acts as an outbox pattern implementation for audit events:
 * 1. Audit events are reliably saved to the database first within the original transaction
 * (using {@link AuditEventService} with REQUIRES_NEW propagation).
 * 2. This scheduler runs periodically, queries for unpublished events, sends them to Kafka,
 * and marks them as published in the database within a single transaction.
 * </p>
 * This ensures audit events are not lost if the Kafka broker is temporarily unavailable
 * during the initial operation.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditEventScheduler {

  private final AuditEventRepository auditEventRepository;
  private final KafkaProducerService kafkaProducerService;

  // Batch size for fetching/publishing events - configurable via properties
  @Value("${iam.scheduler.audit-publish.batch-size:100}")
  private int batchSize;

  /**
   * Scheduled method that runs based on the configured cron expression.
   * It finds unpublished audit events in the database, sends them to Kafka in batches,
   * and updates their status in the database.
   * <p>
   * The entire operation for processing multiple pages runs within a single transaction
   * defined here to ensure consistency between reading unpublished events and marking
   * them as published after attempting to send them.
   * </p>
   */
  @Scheduled(cron = "${iam.scheduler.audit-publish.cron:0 */1 * * * *}") // Default: Run every minute
  @Transactional // Ensures finding unpublished and marking published is atomic per scheduler run
  public void publishAuditEventsToKafka() {
    log.debug("[Audit Scheduler] Starting run to publish audit events...");

    Pageable pageable = PageRequest.of(0, batchSize); // Start with the first page
    Page<AuditEvent> unpublishedEventsPage;
    int totalPublishedInRun = 0;
    int pageNum = 0;
    boolean errorsOccurred = false;

    do {
      // Fetch a batch of unpublished events
      unpublishedEventsPage = auditEventRepository.findByPublishedToKafkaFalseOrderByIdAsc(pageable);
      List<AuditEvent> currentBatchEntities = unpublishedEventsPage.getContent();

      if (currentBatchEntities.isEmpty() && pageNum == 0) {
        log.debug("[Audit Scheduler] No unpublished audit events found.");
        break; // Exit loop early if first page is empty
      } else if (currentBatchEntities.isEmpty()){
        log.debug("[Audit Scheduler] No more unpublished audit events found on page {}.", pageNum);
        break; // Exit loop if current page is empty
      }


      log.info("[Audit Scheduler] Found {} unpublished audit events on page {}. Attempting to publish.",
              currentBatchEntities.size(), pageable.getPageNumber());

      List<Long> idsToMarkPublished = new ArrayList<>();
      List<AuditEventDto> dtosToSend = new ArrayList<>();

      // Prepare DTOs and map Event UUID to DB ID for later update
      // Use a map for efficient lookup of DB ID from Event ID
      Map<UUID, Long> eventIdToDbIdMap = currentBatchEntities.stream()
              .collect(Collectors.toMap(AuditEvent::getEventId, AuditEvent::getId));

      for (AuditEvent entity : currentBatchEntities) {
        dtosToSend.add(AuditEventDto.fromEntity(entity));
      }

      // Send batch to Kafka (currently sends one-by-one, consider batch send in KafkaProducerService)
      for (AuditEventDto dto : dtosToSend) {
        try {
          kafkaProducerService.sendAuditEvent(dto);
          // Assuming async send. If successful *initiation* of send happens,
          // we optimistically add its DB ID to be marked as published.
          // Robustness depends on Kafka producer retries and callback handling.
          // For guaranteed "sent and acknowledged", a more complex tracking mechanism would be needed.
          Long dbId = eventIdToDbIdMap.get(dto.getEventId());
          if (dbId != null) {
            idsToMarkPublished.add(dbId);
          } else {
            log.error("[Audit Scheduler] Could not find DB ID for successfully sent Event ID: {}. Cannot mark as published.", dto.getEventId());
            errorsOccurred = true;
          }
        } catch (Exception e) {
          log.error("[Audit Scheduler] Error triggering send for audit event DTO (ID: {}) to Kafka. Error: {}. Event will remain unpublished.",
                  dto.getEventId(), e.getMessage(), e);
          errorsOccurred = true;
          // Do not add to idsToMarkPublished, it will be retried next run.
        }
      }

      // Update the status for successfully *sent* (or attempted send) events in DB
      if (!CollectionUtils.isEmpty(idsToMarkPublished)) {
        try {
          int updatedCount = auditEventRepository.markAsPublished(idsToMarkPublished);
          log.debug("[Audit Scheduler] Marked {} audit events (page {}) as published in DB. IDs: {}",
                  updatedCount, pageable.getPageNumber(), idsToMarkPublished.size() > 10 ? idsToMarkPublished.size() + " IDs" : idsToMarkPublished);
          if (updatedCount != idsToMarkPublished.size()) {
            log.warn("[Audit Scheduler] Mismatch in marking events published. Expected: {}, Actual: {}. DB IDs: {}",
                    idsToMarkPublished.size(), updatedCount, idsToMarkPublished.size() > 10 ? "..." : idsToMarkPublished);
            errorsOccurred = true; // Log potential inconsistency
          }
          totalPublishedInRun += updatedCount;
        } catch (Exception e) {
          log.error("[Audit Scheduler] Failed to mark audit events as published in DB (page {}). IDs: {}. Error: {}",
                  pageable.getPageNumber(), idsToMarkPublished.size() > 10 ? "..." : idsToMarkPublished, e.getMessage(), e);
          errorsOccurred = true;
          // Transaction might roll back if severe, or these specific events might be resent next run.
        }
      }

      // Prepare for the next page
      pageable = unpublishedEventsPage.nextPageable();
      pageNum++;

    } while (unpublishedEventsPage.hasNext()); // Continue if more pages might exist

    if (totalPublishedInRun > 0 || errorsOccurred) {
      log.info("[Audit Scheduler] Finished publishing run. Total published in this run: {}. Errors occurred: {}",
              totalPublishedInRun, errorsOccurred);
    } else {
      log.debug("[Audit Scheduler] Finished run. No events were published.");
    }
  }

}