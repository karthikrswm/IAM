// File: src/main/java/org/example/iam/config/KafkaConfig.java (iam-consumer version)
package com.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerConfig; // Keep for DLT producer
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer; // Keep for DLT producer key
import com.example.iam.dto.AuditEventDto; // DTO for consumption and DLT publishing
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.*;
import org.springframework.kafka.listener.*;
import org.springframework.kafka.support.serializer.ErrorHandlingDeserializer;
import org.springframework.kafka.support.serializer.FailedDeserializationInfo;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.support.serializer.JsonSerializer; // Keep for DLT producer value
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Configures Spring Kafka components for the IAM Consumer service.
 * Includes Consumer Factory, Listener Container Factory, Error Handling,
 * and Dead-Letter Topic (DLT) configuration.
 * <p>
 * Reads configuration properties from {@code application.properties}.
 * Configures manual acknowledgment and DLT publishing.
 * </p>
 */
@Configuration
@Slf4j
public class KafkaConfig {

  // --- Configuration Properties ---
  @Value("${spring.kafka.bootstrap-servers}")
  private String bootstrapServers;

  @Value("${kafka.topic.audit-events-dlt}")
  private String auditEventDltTopicName; // Need DLT topic name

  // Consumer Group ID
  @Value("${spring.kafka.consumer.group-id:iam-audit-event-consumer-group}")
  private String consumerGroupId;

  // Trusted packages for JSON deserialization
  @Value("${spring.kafka.consumer.properties.spring.json.trusted.packages:org.example.iam.dto,java.util,java.lang}")
  private String trustedPackages;

  // DLT Topic configuration properties (used for topic bean definition)
  @Value("${kafka.topic.audit-events-dlt.partitions:1}")
  private int auditEventDltPartitions;

  @Value("${kafka.topic.audit-events-dlt.replicas:1}")
  private int auditEventDltReplicas;


  // --- DLT Producer Configuration --- (Needed for DeadLetterPublishingRecoverer)

  @Bean
  public ProducerFactory<String, AuditEventDto> dltProducerFactory() {
    Map<String, Object> configProps = new HashMap<>();
    configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
    configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
    configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
    configProps.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, false);
    log.info("Configuring Kafka DLT Producer Factory for bootstrap servers: {}", bootstrapServers);
    return new DefaultKafkaProducerFactory<>(configProps);
  }

  @Bean
  public KafkaTemplate<String, AuditEventDto> dltKafkaTemplate(
      @Qualifier("dltProducerFactory") ProducerFactory<String, AuditEventDto> dltProducerFactory) {
    log.debug("Creating KafkaTemplate bean for DLT.");
    return new KafkaTemplate<>(dltProducerFactory);
  }

  // --- DLT Topic Configuration ---

  @Bean
  public NewTopic auditEventDltTopic() {
    log.info("Defining Kafka DLT topic: Name='{}', Partitions={}, Replicas={}",
        auditEventDltTopicName, auditEventDltPartitions, auditEventDltReplicas);
    if (auditEventDltReplicas > 1 && bootstrapServers.split(",").length < auditEventDltReplicas) {
      log.warn("Kafka DLT topic '{}' replica count ({}) is higher than the number of configured bootstrap servers ({}).",
          auditEventDltTopicName, auditEventDltReplicas, bootstrapServers.split(",").length);
    }
    return TopicBuilder.name(auditEventDltTopicName)
        .partitions(auditEventDltPartitions)
        .replicas(auditEventDltReplicas)
        .build();
  }

  // --- Consumer Configuration ---

  @Bean
  public ConsumerFactory<String, AuditEventDto> consumerFactory() {
    Map<String, Object> props = new HashMap<>();
    props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
    props.put(ConsumerConfig.GROUP_ID_CONFIG, consumerGroupId);
    props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false"); // Manual ACK

    props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
    props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ErrorHandlingDeserializer.class);
    props.put(ErrorHandlingDeserializer.VALUE_DESERIALIZER_CLASS, JsonDeserializer.class.getName());
    props.put(ErrorHandlingDeserializer.VALUE_FUNCTION, FailedDeserializationFunction.class.getName());

    props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, AuditEventDto.class.getName());
    props.put(JsonDeserializer.USE_TYPE_INFO_HEADERS, "false");

    if (!StringUtils.hasText(trustedPackages) || trustedPackages.equals("*")) {
      log.warn("Kafka consumer trusted packages set to '{}'. This is insecure for production. Configure 'spring.kafka.consumer.properties.spring.json.trusted.packages' specifically.",
          trustedPackages);
    } else {
      if (!trustedPackages.contains("java.util")) trustedPackages += ",java.util";
      if (!trustedPackages.contains("java.lang")) trustedPackages += ",java.lang";
      log.debug("Effective Kafka trusted packages: {}", trustedPackages);
    }
    props.put(JsonDeserializer.TRUSTED_PACKAGES, trustedPackages);

    log.info("Configuring Kafka Consumer Factory: BootstrapServers='{}', GroupId='{}', EnableAutoCommit=false, TrustedPackages='{}'",
        bootstrapServers, consumerGroupId, trustedPackages);

    return new DefaultKafkaConsumerFactory<>(props);
  }

  // --- Error Handling & DLT ---

  @Bean
  public DeadLetterPublishingRecoverer deadLetterPublishingRecoverer(
      @Qualifier("dltKafkaTemplate") KafkaTemplate<String, AuditEventDto> dltKafkaTemplate) {

    log.info("Configuring DeadLetterPublishingRecoverer for topic: {}", auditEventDltTopicName);
    BiFunction<ConsumerRecord<?, ?>, Exception, TopicPartition> destinationResolver = (cr, e) ->
        new TopicPartition(auditEventDltTopicName, 0);

    DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(dltKafkaTemplate, destinationResolver);
    // Default headers are added automatically.
    return recoverer;
  }

  @Bean
  public DefaultErrorHandler defaultErrorHandler(DeadLetterPublishingRecoverer deadLetterPublishingRecoverer) {
    log.info("Configuring DefaultErrorHandler with DeadLetterPublishingRecoverer.");
    // Configure without retries (send immediately to DLT on first failure)
    DefaultErrorHandler errorHandler = new DefaultErrorHandler(deadLetterPublishingRecoverer);
    // Configure with retries (Example: 2 attempts with 1 second fixed delay)
    // FixedBackOff backOff = new FixedBackOff(1000L, 2);
    // DefaultErrorHandler errorHandler = new DefaultErrorHandler(deadLetterPublishingRecoverer, backOff);
    errorHandler.setLogLevel(KafkaException.Level.WARN);
    return errorHandler;
  }

  // --- Listener Container Factory ---

  @Bean
  public ConcurrentKafkaListenerContainerFactory<String, AuditEventDto> kafkaListenerContainerFactory(
      ConsumerFactory<String, AuditEventDto> consumerFactory,
      CommonErrorHandler defaultErrorHandler
  ) {
    ConcurrentKafkaListenerContainerFactory<String, AuditEventDto> factory =
        new ConcurrentKafkaListenerContainerFactory<>();
    factory.setConsumerFactory(consumerFactory);
    factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
    factory.setCommonErrorHandler(defaultErrorHandler);

    log.info("Configuring Kafka Listener Container Factory with Manual AckMode and DefaultErrorHandler (DLT enabled).");
    return factory;
  }

  // --- Deserialization Failure Handler ---

  public static class FailedDeserializationFunction implements Function<FailedDeserializationInfo, AuditEventDto> {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FailedDeserializationFunction.class);

    @Override
    public AuditEventDto apply(FailedDeserializationInfo info) {
      log.error("!!! Failed to deserialize Kafka message. Topic='{}'. Reason: {} !!!",
          info.getTopic(), info.getException().getMessage(), info.getException());
      log.error("Failed Deserialization Headers: {}", info.getHeaders());
      log.error("Failed Deserialization Raw Data (first 100 bytes): {}",
          Arrays.toString(Arrays.copyOf(info.getData(), Math.min(100, info.getData().length))));
      return null; // Skip record
    }
  }
}