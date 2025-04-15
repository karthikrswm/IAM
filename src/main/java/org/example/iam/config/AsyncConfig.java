// File: src/main/java/org/example/iam/config/AsyncConfig.java
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Configuration class to enable and customize asynchronous method execution capabilities
 * provided by Spring's {@code @Async} annotation.
 * <p>
 * This configuration defines a specific {@link ThreadPoolTaskExecutor} bean to manage
 * threads used for asynchronous tasks, such as sending emails or logging audit events,
 * preventing them from blocking the main application threads (e.g., web request threads).
 * Using a custom executor allows for fine-grained control over thread pool behavior.
 * </p>
 */
@Configuration
@EnableAsync // Enables Spring's detection and processing of @Async annotations on beans.
@Slf4j
public class AsyncConfig {

  // --- Constants for Thread Pool Configuration ---
  // These could be externalized to application.properties if more dynamic configuration is needed.
  private static final int CORE_POOL_SIZE = 5;
  private static final int MAX_POOL_SIZE = 10;
  private static final int QUEUE_CAPACITY = 25;
  private static final String THREAD_NAME_PREFIX = "Async-IAM-";

  /**
   * Defines a custom {@link ThreadPoolTaskExecutor} bean named "taskExecutor" for handling
   * {@code @Async} method calls.
   * <p>
   * This executor provides better resource management compared to the default
   * {@code SimpleAsyncTaskExecutor} by maintaining a pool of threads and a queue for pending tasks.
   * </p>
   * <ul>
   * <li>{@code corePoolSize}: The number of threads to keep in the pool, even if they are idle.</li>
   * <li>{@code maxPoolSize}: The maximum number of threads allowed in the pool.</li>
   * <li>{@code queueCapacity}: The number of tasks to queue up before creating new threads (up to maxPoolSize).</li>
   * <li>{@code threadNamePrefix}: A prefix for the names of threads created by this pool, useful for logging and debugging.</li>
   * </ul>
   *
   * @return A configured {@link Executor} bean ready for use with {@code @Async}.
   */
  @Bean(name = "taskExecutor") // Standard bean name recognized by @Async by default.
  public Executor taskExecutor() {
    log.info("Initializing ThreadPoolTaskExecutor for @Async tasks (Core: {}, Max: {}, Queue: {})",
            CORE_POOL_SIZE, MAX_POOL_SIZE, QUEUE_CAPACITY);

    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(CORE_POOL_SIZE);
    executor.setMaxPoolSize(MAX_POOL_SIZE);
    executor.setQueueCapacity(QUEUE_CAPACITY);
    executor.setThreadNamePrefix(THREAD_NAME_PREFIX);

    // Optional: Define behavior when the queue is full and max pool size is reached.
    // Default is AbortPolicy, which throws an exception. Other options include
    // CallerRunsPolicy, DiscardPolicy, DiscardOldestPolicy.
    // executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

    executor.initialize(); // Important: Initializes the executor.
    log.debug("ThreadPoolTaskExecutor '{}' initialized successfully.", "taskExecutor");
    return executor;
  }

  /*
   * Note: If the application requires different types of asynchronous tasks
   * (e.g., short-lived vs. long-running, critical vs. non-critical), multiple
   * Executor beans can be defined with distinct configurations. Specific methods
   * can then target a particular executor using `@Async("beanName")`.
   * Example:
   *
   * @Bean(name = "emailTaskExecutor")
   * public Executor emailTaskExecutor() { ... config ... }
   *
   * @Async("emailTaskExecutor")
   * public void sendEmailAsync(...) { ... }
   */
}