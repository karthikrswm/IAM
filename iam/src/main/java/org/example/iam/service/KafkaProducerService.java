// File: src/main/java/org/example/iam/service/KafkaProducerService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.dto.AuditEventDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;
// Removed CompletableFuture import as it's used within the method scope
import java.util.concurrent.CompletableFuture;


/**
 * Service responsible for producing and sending messages to Kafka topics.
 * <p>
 * It encapsulates the interaction with Spring's {@link KafkaTemplate}, providing specific methods
 * for sending different types of messages (currently {@link AuditEventDto}). It handles
 * asynchronous sending and includes basic logging for success and failure callbacks.
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class KafkaProducerService {

  /**
   * Configured KafkaTemplate for sending messages with String keys and AuditEventDto values.
   */
  private final KafkaTemplate<String, AuditEventDto> kafkaTemplate;

  /**
   * Name of the Kafka topic designated for audit events, injected from application properties.
   */
  @Value("${kafka.topic.audit-events}")
  private String auditEventTopicName;

  /**
   * Sends an {@link AuditEventDto} message asynchronously to the configured audit events Kafka topic.
   * <p>
   * Uses the {@link AuditEventDto#getEventId()} (UUID converted to String) as the Kafka message key.
   * This helps in partitioning messages potentially based on the event source or for log compaction strategies.
   * </p>
   * <p>
   * The send operation is asynchronous. Success or failure is logged via callbacks attached
   * to the {@link CompletableFuture} returned by the KafkaTemplate. If sending fails,
   * an error is logged, but the exception is not propagated synchronously. The
   * {@link AuditEventScheduler} relies on the database flag (`publishedToKafka`) not being updated
   * in case of send failures to ensure retries on subsequent scheduler runs.
   * </p>
   *
   * @param eventDto The {@link AuditEventDto} to send. Method handles null DTOs or DTOs with null eventId gracefully.
   */
  public void sendAuditEvent(AuditEventDto eventDto) {
    // Basic validation before attempting to send
    if (eventDto == null || eventDto.getEventId() == null) {
      log.warn("Attempted to send null or invalid AuditEventDto (missing eventId) to Kafka topic '{}'. Skipping.", auditEventTopicName);
      return;
    }

    // Use eventId (UUID) as the Kafka message key for potential partitioning or compaction benefits.
    String key = eventDto.getEventId().toString();
    log.debug("Attempting to send AuditEventDto (ID: {}) to Kafka topic '{}'", key, auditEventTopicName);

    // Send the message asynchronously using KafkaTemplate.sendDefault() or send(topic, key, payload)
    CompletableFuture<SendResult<String, AuditEventDto>> future = kafkaTemplate.send(auditEventTopicName, key, eventDto);

    // Add callbacks to handle the asynchronous result (success or failure)
    future.whenComplete((sendResult, exception) -> {
      if (exception == null) {
        // --- Success Case ---
        // Log details including partition and offset upon successful send acknowledgment from Kafka broker.
        log.trace("Successfully sent AuditEventDto (ID: {}) to Kafka. Topic='{}', Partition={}, Offset={}",
                key,
                sendResult.getRecordMetadata().topic(),      // Use metadata from result
                sendResult.getRecordMetadata().partition(),
                sendResult.getRecordMetadata().offset());
      } else {
        // --- Failure Case ---
        // Log the error robustly, including the exception message and potentially parts of the DTO for diagnosis.
        // Avoid logging the full DTO if it contains sensitive info not already masked.
        log.error("!!! Failed to send AuditEventDto (ID: {}) to Kafka topic '{}'. Error: {} !!!",
                key, auditEventTopicName, exception.getMessage(), exception);
        // Note: The AuditEventScheduler relies on the fact that the 'publishedToKafka' flag
        // in the database is *not* updated when this send fails, allowing for a retry on the next schedule.
        // For more advanced scenarios, implement specific retry logic here or configure Kafka producer retries,
        // or implement a Dead-Letter Queue (DLQ) strategy.
      }
    });
  }

  // Add methods for sending other types of DTOs to different topics if needed
  // public void sendOtherMessage(OtherDto otherDto) { ... }
}