package io.mosip.certify.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for Status List management
 */
@Configuration
@ConfigurationProperties(prefix = "statuslist")
public class StatusListConfig {

    /**
     * Percentage of status list capacity that can be used before marking it as full
     * Default: 50 (means 50% of total capacity)
     */
    private int usableCapacity = 50;

    /**
     * Maximum number of attempts for index assignment operations
     * Default: 10
     */
    private int maxAttempts = 10;

    /**
     * Strategy for index assignment
     * Options: "database_random", "bloomfilter", etc.
     * Default: "database_random"
     */
    private String indexAssignmentStrategy = "database_random";

    /**
     * Whether to automatically populate indices when a new status list is created
     * Default: true
     */
    private boolean autoPopulateIndices = true;

    /**
     * Batch size for populating indices
     * Default: 1000
     */
    private int indexPopulationBatchSize = 1000;

    // Getters and Setters

    public int getUsableCapacity() {
        return usableCapacity;
    }

    public void setUsableCapacity(int usableCapacity) {
        this.usableCapacity = usableCapacity;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    public String getIndexAssignmentStrategy() {
        return indexAssignmentStrategy;
    }

    public void setIndexAssignmentStrategy(String indexAssignmentStrategy) {
        this.indexAssignmentStrategy = indexAssignmentStrategy;
    }

    public boolean isAutoPopulateIndices() {
        return autoPopulateIndices;
    }

    public void setAutoPopulateIndices(boolean autoPopulateIndices) {
        this.autoPopulateIndices = autoPopulateIndices;
    }

    public int getIndexPopulationBatchSize() {
        return indexPopulationBatchSize;
    }

    public void setIndexPopulationBatchSize(int indexPopulationBatchSize) {
        this.indexPopulationBatchSize = indexPopulationBatchSize;
    }
}