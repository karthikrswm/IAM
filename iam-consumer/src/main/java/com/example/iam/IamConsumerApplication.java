// File: iam-consumer/src/main/java/org/example/iam/consumer/IamConsumerApplication.java
package com.example.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.kafka.annotation.EnableKafka; // Optional: Explicitly enable Kafka

@SpringBootApplication
@EnableKafka // Ensure Kafka listeners are activated
// Scan config, service, dto in org.example.iam packages
public class IamConsumerApplication {

	public static void main(String[] args) {
		SpringApplication.run(IamConsumerApplication.class, args);
		System.out.println("---- IAM Consumer Application Started ----"); // Basic startup message
	}

}