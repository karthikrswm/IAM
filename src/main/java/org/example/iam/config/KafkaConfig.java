// File: src/main/java/org/example/iam/config/KafkaConfig.java
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig; // Import ConsumerConfig
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer; // Import StringDeserializer
import org.apache.kafka.common.serialization.StringSerializer;
import org.example.iam.dto.AuditEventDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory; // Import Listener Factory
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.*; // Import core Kafka classes (ProducerFactory, ConsumerFactory, KafkaTemplate, Default...)
import org.springframework.kafka.listener.ContainerProperties; // Import ContainerProperties for AckMode
import org.springframework.kafka.support.serializer.ErrorHandlingDeserializer; // Import ErrorHandlingDeserializer
import org.springframework.kafka.support.serializer.FailedDeserializationInfo;
import org.springframework.kafka.support.serializer.JsonDeserializer; // Import JsonDeserializer
import org.springframework.kafka.support.serializer.JsonSerializer;
import org.springframework.util.StringUtils; // Import StringUtils

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Configures Spring Kafka components, including Producer, Consumer, Topic creation,
 * and Listener Container Factory for the IAM application.
 * <p>
 * Reads configuration properties (like bootstrap servers, topic names, group ID)
 * from {@code application.properties}.
 * </p>
 */
@Configuration
@Slf4j
public class KafkaConfig {

    // --- Configuration Properties ---
    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${kafka.topic.audit-events}")
    private String auditEventTopicName;

    // Consumer Group ID - Default value provided if property is missing
    @Value("${spring.kafka.consumer.group-id:iam-internal-audit-consumer}")
    private String consumerGroupId;

    // Trusted packages for JSON deserialization (important for security)
    // Use specific package, avoid '*' in production if possible.
    @Value("${spring.kafka.consumer.properties.spring.json.trusted.packages:org.example.iam.dto}")
    private String trustedPackages;

    // --- Producer Configuration ---

    /**
     * Defines the Kafka Producer Factory, responsible for creating Kafka Producer instances.
     * Configures the bootstrap servers and serializers for message keys (String) and
     * values (JSON - AuditEventDto).
     *
     * @return A configured {@link ProducerFactory}.
     */
    @Bean
    public ProducerFactory<String, AuditEventDto> producerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        // Disable adding type info headers by default for cleaner messages,
        // consumers can be configured with a default type.
        configProps.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, false);

        log.info("Configuring Kafka Producer Factory for bootstrap servers: {}", bootstrapServers);
        return new DefaultKafkaProducerFactory<>(configProps);
    }

    /**
     * Defines the KafkaTemplate bean, providing a high-level abstraction for sending messages.
     * Uses the configured {@link ProducerFactory}.
     *
     * @return A configured {@link KafkaTemplate}.
     */
    @Bean
    public KafkaTemplate<String, AuditEventDto> kafkaTemplate() {
        log.debug("Creating KafkaTemplate bean.");
        return new KafkaTemplate<>(producerFactory());
    }

    // --- Topic Configuration ---

    /**
     * Defines the Kafka topic for audit events using {@link TopicBuilder}.
     * Configures topic name, number of partitions, and replication factor.
     * Spring Boot Admin client will automatically create this topic if it doesn't exist
     * (requires an AdminClient bean, often auto-configured).
     *
     * @return A {@link NewTopic} bean representing the desired topic configuration.
     */
    @Bean
    public NewTopic auditEventTopic() {
        int partitions = 3; // Example: Use 3 partitions for potential parallelism
        int replicas = 1;   // Example: Use 1 replica for local/dev setup (Increase for HA in prod)
        log.info("Defining Kafka topic: Name='{}', Partitions={}, Replicas={}",
            auditEventTopicName, partitions, replicas);
        return TopicBuilder.name(auditEventTopicName)
            .partitions(partitions)
            .replicas(replicas) // Adjust replicas based on Kafka cluster size
            .build();
    }

    // --- Consumer Configuration ---

    /**
     * Configures the Kafka Consumer Factory.
     * Sets bootstrap servers, consumer group ID, and deserializers for keys (String)
     * and values (JSON - AuditEventDto). Includes configuration for trusted packages
     * for JSON deserialization security. Wraps the value deserializer with
     * {@link ErrorHandlingDeserializer} for resilience against poison pill messages.
     *
     * @return A configured {@link ConsumerFactory}.
     */
    @Bean
    public ConsumerFactory<String, AuditEventDto> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroupId);
        // Start consuming from the earliest offset if no offset is found for the group.
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        // Let the container manage commits based on listener success/failure (default is BATCH mode).
        // Set to "false" if using manual acknowledgment in the listener.
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "true"); // Changed to true to rely on container commits

        // --- Key Deserializer ---
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);

        // --- Value Deserializer (with Error Handling) ---
        // Use ErrorHandlingDeserializer to gracefully handle messages that cannot be deserialized.
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ErrorHandlingDeserializer.class);
        // Delegate the actual deserialization to JsonDeserializer.
        props.put(ErrorHandlingDeserializer.VALUE_DESERIALIZER_CLASS, JsonDeserializer.class.getName());

        // Configure the delegate JsonDeserializer properties via ErrorHandlingDeserializer prefix.
        // Define a function to handle failed deserializations (e.g., log and return null).
        props.put(ErrorHandlingDeserializer.VALUE_FUNCTION, FailedDeserializationFunction.class.getName()); // Use custom function class

        // Configure JsonDeserializer specifics
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, AuditEventDto.class.getName()); // Default type if no type headers
        props.put(JsonDeserializer.USE_TYPE_INFO_HEADERS, "false"); // Don't rely on type headers from producer

        // ** IMPORTANT SECURITY CONFIGURATION **
        // Define trusted packages to prevent deserialization of arbitrary classes.
        if (!StringUtils.hasText(trustedPackages) || trustedPackages.equals("*")) {
            log.warn("Kafka consumer trusted packages set to '{}'. This is insecure for production. " +
                    "Configure 'spring.kafka.consumer.properties.spring.json.trusted.packages' specifically.",
                trustedPackages);
        }
        props.put(JsonDeserializer.TRUSTED_PACKAGES, trustedPackages); // Use configured trusted packages

        log.info("Configuring Kafka Consumer Factory: BootstrapServers='{}', GroupId='{}', TrustedPackages='{}'",
            bootstrapServers, consumerGroupId, trustedPackages);

        return new DefaultKafkaConsumerFactory<>(props);
    }

    /**
     * Configures the Kafka Listener Container Factory, which creates containers for methods
     * annotated with {@code @KafkaListener}.
     * Uses the configured {@link ConsumerFactory}. Sets container properties like concurrency
     * and acknowledgment mode.
     *
     * @return A configured {@link ConcurrentKafkaListenerContainerFactory}.
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, AuditEventDto> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, AuditEventDto> factory =
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());

        // Optional: Configure concurrency (number of listener threads per container).
        // Useful if processing order within a partition is not strictly required and higher throughput is needed.
        // factory.setConcurrency(3); // Example: Run 3 listener threads

        // Optional: Configure acknowledgment mode. Default is BATCH.
        // - RECORD: Ack after each record is processed by the listener.
        // - MANUAL_IMMEDIATE: Listener must explicitly call Acknowledgment.acknowledge().
        // factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.RECORD);

        // Optional: Configure error handling at the container level (e.g., retries, dead-letter topics)
        // factory.setCommonErrorHandler(...)

        log.info("Configuring Kafka Listener Container Factory with default settings (AckMode: BATCH).");
        return factory;
    }

    /**
     * A function implementation used by {@link ErrorHandlingDeserializer} to handle
     * records that fail deserialization. This implementation logs the error and returns null,
     * effectively skipping the poison pill message.
     */
    public static class FailedDeserializationFunction implements Function<FailedDeserializationInfo, AuditEventDto> {
        // Static logger instance for the static nested class
        private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FailedDeserializationFunction.class);

        @Override
        public AuditEventDto apply(FailedDeserializationInfo info) {
            // *** CORRECTED LOG MESSAGE ***
            // Removed info.getPartition() and info.getOffset() as they don't exist here.
            log.error("!!! Failed to deserialize Kafka message. Topic='{}'. Reason: {} !!!",
                    info.getTopic(), // Topic is available
                    info.getException().getMessage(), // Exception message is available
                    info.getException()); // Log the full exception for stack trace details

            // Optionally, log headers or raw data if needed for deep debugging, but be mindful of size/sensitivity.
             log.error("Failed Deserialization Headers: {}", info.getHeaders());
             log.error("Failed Deserialization Raw Data (first 100 bytes): {}",
                      Arrays.toString(Arrays.copyOf(info.getData(), Math.min(100, info.getData().length))));

            // Returning null causes the ErrorHandlingDeserializer to skip this record.
            return null;
        }
    }
}