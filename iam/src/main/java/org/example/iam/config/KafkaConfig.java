// File: src/main/java/org/example/iam/config/KafkaConfig.java (iam-service version)
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.example.iam.dto.AuditEventDto; // Needed for template type
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.*;
import org.springframework.kafka.support.serializer.JsonSerializer;
// Removed consumer/error handling/DLT imports

import java.util.HashMap;
import java.util.Map;

/**
 * Configures Spring Kafka components for the main IAM Service (Producer-focused).
 * Includes Producer configuration and main Audit Event Topic creation.
 * <p>
 * Reads configuration properties from {@code application.properties}.
 * </p>
 */
@Configuration
@Slf4j
public class KafkaConfig {

    // --- Configuration Properties ---
    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers; // Used by producer and admin client for topic creation

    @Value("${kafka.topic.audit-events}")
    private String auditEventTopicName;

    // Topic configuration properties (used for topic bean definition)
    @Value("${kafka.topic.audit-events.partitions:3}")
    private int auditEventPartitions;

    @Value("${kafka.topic.audit-events.replicas:1}")
    private int auditEventReplicas;


    // --- Producer Configuration (Main Topic) ---

    /**
     * Defines the Kafka Producer Factory for the main audit events topic.
     * @return A configured {@link ProducerFactory}.
     */
    @Bean
    public ProducerFactory<String, AuditEventDto> producerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        // Ensure producer doesn't add type headers if consumer isn't expecting them
        configProps.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, false);

        log.info("Configuring Kafka Producer Factory for bootstrap servers: {}", bootstrapServers);
        return new DefaultKafkaProducerFactory<>(configProps);
    }

    /**
     * Defines the KafkaTemplate bean for sending messages to the main audit topic.
     * @param producerFactory The producer factory for the main topic.
     * @return A configured {@link KafkaTemplate}.
     */
    @Bean
    public KafkaTemplate<String, AuditEventDto> kafkaTemplate(ProducerFactory<String, AuditEventDto> producerFactory) {
        log.debug("Creating KafkaTemplate bean for AuditEventDto.");
        return new KafkaTemplate<>(producerFactory);
    }

    // --- Topic Configuration ---

    /**
     * Defines the Kafka topic for audit events using properties for partitions/replicas.
     * @return A {@link NewTopic} bean representing the desired topic configuration.
     */
    @Bean
    public NewTopic auditEventTopic() {
        log.info("Defining Kafka topic: Name='{}', Partitions={}, Replicas={}",
                auditEventTopicName, auditEventPartitions, auditEventReplicas);
        if (auditEventReplicas > 1 && bootstrapServers.split(",").length < auditEventReplicas) {
            log.warn("Kafka topic '{}' replica count ({}) is higher than the number of configured bootstrap servers ({}).",
                    auditEventTopicName, auditEventReplicas, bootstrapServers.split(",").length);
        }
        return TopicBuilder.name(auditEventTopicName)
                .partitions(auditEventPartitions)
                .replicas(auditEventReplicas)
                .build();
    }

    // --- Consumer, Error Handling, and DLT beans are REMOVED from iam-service ---

}