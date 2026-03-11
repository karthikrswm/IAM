// File: src/main/java/org/example/iam/service/AuditEventConsumer.java
package com.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.example.iam.dto.AuditEventDto;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment; // <<< ADDED import for manual acknowledgment
import org.springframework.kafka.support.KafkaHeaders; // Standard Kafka message headers
import org.springframework.messaging.handler.annotation.Header; // Annotation for accessing headers
import org.springframework.messaging.handler.annotation.Payload; // Annotation for accessing message payload
import org.springframework.stereotype.Service;

/**
 * Kafka consumer service responsible for listening to the configured audit event topic
 * (defined by {@code kafka.topic.audit-events} property) and processing received
 * audit event messages.
 * <p>
 * Uses Spring Kafka's {@link KafkaListener @KafkaListener} annotation to automatically
 * receive messages. The configuration (group ID, container factory, deserialization, error handling, manual ack)
 * is defined in {@link org.example.iam.config.KafkaConfig}.
 * </p>
 * <p>
 * Processing logic includes logging and simulating forwarding to another system. Uses manual
 * acknowledgment to confirm processing. Errors are re-thrown to leverage the configured
 * container error handler (e.g., DLT publishing).
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditEventConsumer {

  // Inject other services here if needed for processing the event, e.g.:
  // private final ElasticsearchService elasticsearchService;
  // private final AlertingService alertingService;

  /**
   * Listens to the Kafka topic specified by {@code kafka.topic.audit-events}.
   * Deserializes the message payload into an {@link AuditEventDto} and processes it.
   * Requires manual acknowledgment. Handles potential errors during processing by re-throwing.
   *
   * @param eventDto       The deserialized audit event data from the Kafka message payload.
   * @param key            The Kafka message key (typically the event UUID as a string).
   * @param partition      The Kafka partition from which the message was received.
   * @param offset         The message offset within the partition.
   * @param topic          The Kafka topic from which the message was received.
   * @param acknowledgment The acknowledgment object for manual commit control. // <<< ADDED parameter
   */
  @KafkaListener(
      topics = "${kafka.topic.audit-events}", // Topic name from properties
      groupId = "${spring.kafka.consumer.group-id:iam-internal-audit-consumer}", // Group ID from properties or default
      containerFactory = "kafkaListenerContainerFactory" // Reference the factory bean defined in KafkaConfig
      // Ensure containerFactory is configured for MANUAL_IMMEDIATE AckMode in KafkaConfig
      // Optional: Add concurrency = "3" to run multiple threads if needed
  )
  public void consumeAuditEvent(
      // Use @Payload to bind the deserialized message body
      @Payload AuditEventDto eventDto,
      // Use @Header to access specific Kafka message headers
      @Header(KafkaHeaders.RECEIVED_KEY) String key,
      @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
      @Header(KafkaHeaders.OFFSET) long offset,
      @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
      // Inject Acknowledgment for manual ack
      Acknowledgment acknowledgment // <<< ADDED parameter
  ) {

    // Check if DTO is null (could happen if deserialization fails and FailedDeserializationFunction returns null)
    if (eventDto == null) {
      log.warn("Received null AuditEventDto message (likely due to prior deserialization error). Key: {}, Partition: {}, Offset: {}, Topic: {}. Acknowledging to skip.",
          key, partition, offset, topic);
      // Acknowledge manually here because the ErrorHandlingDeserializer function returned null,
      // preventing the listener from processing normally. We want to commit the offset for this null payload.
      acknowledgment.acknowledge(); // <<< ACKNOWLEDGE null message
      return;
    }

    log.info("Consumed Audit Event: Key='{}', Partition={}, Offset={}, Topic='{}', EventType='{}', Actor='{}', Timestamp='{}'",
        key, partition, offset, topic,
        eventDto.getEventType(), eventDto.getActor(), eventDto.getEventTimestamp());

    // --- Processing Logic ---
    // Implement the actual handling of the consumed audit event here.
    try {
      // Example: Log details at debug level
      log.debug("Processing Consumed Event Details: {}", eventDto);

      // >>> Simulate forwarding to another system (e.g., Log Aggregation, SIEM) <<<
      simulateForwarding(eventDto);
      // Example: Send to another system (e.g., Elasticsearch)
      // if (elasticsearchService != null) {
      //     elasticsearchService.indexAuditEvent(eventDto);
      // }

      // Example: Trigger alert based on specific event type
      // if ("ACCOUNT_LOCKED".equals(eventDto.getEventType()) && alertingService != null) {
      //     alertingService.triggerAccountLockoutAlert(eventDto.getActor(), eventDto.getOrganizationId());
      // }

      // ---> Acknowledge the message after successful processing <---
      acknowledgment.acknowledge(); // <<< MANUALLY ACKNOWLEDGE
      log.debug("Manual acknowledgment sent for offset {}", offset);

    } catch (Exception e) {
      // Log processing errors robustly
      log.error("!!! Error processing consumed audit event (Key: {}, Offset: {}). Error: {} !!!",
          key, offset, e.getMessage(), e);

      // --- Error Handling Strategy with Manual Ack ---
      // DO NOT acknowledge here. Re-throwing the exception allows the
      // configured CommonErrorHandler (e.g., DefaultErrorHandler with DLT)
      // in the listener container factory to handle the failure (e.g., retries, DLT publishing).
      // If we acknowledged here, the message offset would be committed, and it wouldn't be retried or sent to DLT.
      throw new RuntimeException("Failed to process audit event key: " + key + ", Offset: " + offset, e); // Re-throw
    }
  }

  /**
   * Placeholder method simulating forwarding the processed audit event to an external system.
   * In a real application, this would interact with another service (e.g., Elasticsearch client, HTTP client).
   * @param eventDto The processed event DTO.
   */
  private void simulateForwarding(AuditEventDto eventDto) {
    // Simulate processing time (optional)
    // try { Thread.sleep(10); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }

    // Log simulation message
    log.debug("Simulating forwarding Audit Event ID '{}' (Type: {}) to external system/log aggregator.",
        eventDto.getEventId(), eventDto.getEventType());
    // Replace with actual integration logic:
    // externalLogService.send(eventDto);
    // or restTemplate.postForObject("http://log-aggregator/events", eventDto, Void.class);
  }
}