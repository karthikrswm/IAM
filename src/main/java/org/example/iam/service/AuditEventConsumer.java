// File: src/main/java/org/example/iam/service/AuditEventConsumer.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.dto.AuditEventDto;
import org.springframework.kafka.annotation.KafkaListener;
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
 * receive messages. The configuration (group ID, container factory, deserialization)
 * is defined in {@link org.example.iam.config.KafkaConfig}.
 * </p>
 * <p>
 * Currently, the processing logic simply logs the received event details. In a real
 * application, this service would integrate with other systems like log aggregation
 * (Elasticsearch, Splunk), SIEM, or real-time alerting platforms.
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
   * Handles potential errors during processing.
   *
   * @param eventDto  The deserialized audit event data from the Kafka message payload.
   * @param key       The Kafka message key (typically the event UUID as a string).
   * @param partition The Kafka partition from which the message was received.
   * @param offset    The message offset within the partition.
   * @param topic     The Kafka topic from which the message was received.
   */
  @KafkaListener(
          topics = "${kafka.topic.audit-events}", // Topic name from properties
          groupId = "${spring.kafka.consumer.group-id:iam-internal-audit-consumer}", // Group ID from properties or default
          containerFactory = "kafkaListenerContainerFactory" // Reference the factory bean defined in KafkaConfig
          // Optional: Add concurrency = "3" to run multiple threads if needed
  )
  public void consumeAuditEvent(
          // Use @Payload to bind the deserialized message body
          @Payload AuditEventDto eventDto,
          // Use @Header to access specific Kafka message headers
          @Header(KafkaHeaders.RECEIVED_KEY) String key,
          @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
          @Header(KafkaHeaders.OFFSET) long offset,
          @Header(KafkaHeaders.RECEIVED_TOPIC) String topic) {

    // Check if DTO is null (could happen if deserialization fails and FailedDeserializationFunction returns null)
    if (eventDto == null) {
      log.warn("Received null AuditEventDto message (likely due to prior deserialization error). Key: {}, Partition: {}, Offset: {}, Topic: {}",
              key, partition, offset, topic);
      // Acknowledge manually here if using manual ack mode and skipping poison pills.
      // With default container commit, this message offset will be committed if no exception is thrown.
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

      // Example: Send to another system (e.g., Elasticsearch)
      // if (elasticsearchService != null) {
      //     elasticsearchService.indexAuditEvent(eventDto);
      // }

      // Example: Trigger alert based on specific event type
      // if ("ACCOUNT_LOCKED".equals(eventDto.getEventType()) && alertingService != null) {
      //     alertingService.triggerAccountLockoutAlert(eventDto.getActor(), eventDto.getOrganizationId());
      // }

      // If using manual acknowledgment (AckMode.MANUAL_IMMEDIATE):
      // Acknowledgment acknowledgment // Add as method parameter
      // acknowledgment.acknowledge();
      // log.debug("Manual acknowledgment sent for offset {}", offset);

    } catch (Exception e) {
      // Log processing errors robustly
      log.error("!!! Error processing consumed audit event (Key: {}, Offset: {}). Error: {} !!!",
              key, offset, e.getMessage(), e);

      // Error Handling Strategy:
      // 1. Retry: Configure Kafka listener container for retries (requires stateful retry logic or idempotent processing).
      // 2. Dead-Letter Queue (DLQ): Configure container to send failed messages to a DLQ topic for later analysis.
      // 3. Log and Skip: (Current behavior) Log the error. If not using manual ack, the offset might still be committed depending on container config.
      //    If using manual ack, DO NOT acknowledge here if you want the message to be redelivered (potentially indefinitely).

      // Rethrowing the exception might cause the container to retry (depending on config)
      // throw new RuntimeException("Failed to process audit event key: " + key, e);
    }
  }
}