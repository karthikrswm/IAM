-- V4__Add_AuditEvent_Kafka_Flag.sql
-- Adds the flag and index needed by the AuditEventScheduler to track Kafka publishing status.
-- No syntax changes needed for MySQL 5.x compatibility.

ALTER TABLE audit_events
    ADD COLUMN published_to_kafka BOOLEAN NOT NULL DEFAULT FALSE AFTER details;

-- Add an index to efficiently query for unpublished events
CREATE INDEX idx_audit_published_status ON audit_events (published_to_kafka);