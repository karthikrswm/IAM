// File: src/main/java/org/example/iam/config/SchedulerConfig.java
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

/**
 * Configuration class to enable Spring's scheduled task execution capabilities.
 * <p>
 * The {@link EnableScheduling @EnableScheduling} annotation detects methods annotated
 * with {@link org.springframework.scheduling.annotation.Scheduled @Scheduled} within
 * Spring-managed beans and runs them according to their defined cron expressions or fixed rates.
 * </p>
 * <p>
 * By default, Spring Boot provides a default task scheduler (a single-threaded executor).
 * If more control is needed (e.g., a multi-threaded scheduler), a custom
 * {@link java.util.concurrent.ScheduledExecutorService} bean can be defined, and this class
 * can implement {@link SchedulingConfigurer} to configure its usage.
 * </p>
 */
@Configuration
@EnableScheduling // Enables detection and execution of @Scheduled tasks.
@Slf4j
public class SchedulerConfig implements SchedulingConfigurer {

    /**
     * Configures the task registrar, primarily used if a custom task executor/scheduler is defined.
     * In the default case (using Spring Boot's auto-configured scheduler), this method might not
     * be strictly necessary, but it provides a hook for future customization.
     *
     * @param taskRegistrar The registrar for scheduled tasks.
     */
    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        log.info("Spring Scheduling enabled. Using default task scheduler unless a custom one is configured.");
        // If a custom TaskScheduler bean named "taskScheduler" (or similar) exists,
        // you could set it here:
        // taskRegistrar.setScheduler(customTaskScheduler());
    }

    /*
     // Example of defining a custom scheduler bean (if needed)
     @Bean(destroyMethod = "shutdown")
     public Executor customTaskScheduler() {
         ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5); // Example: 5 threads
         log.info("Configuring custom ScheduledThreadPoolExecutor for @Scheduled tasks.");
         return scheduler;
     }
     */
}