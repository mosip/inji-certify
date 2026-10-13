# Build context: the inji-certify repository root.
# Build and test the Maven artifacts before building this runtime image.
ARG CERTIFY_BASE_IMAGE=injistack/inji-certify:0.14.0
FROM ${CERTIFY_BASE_IMAGE}

ARG CERTIFY_VERSION=0.14.0

# Replace the base service with this fork's compatible implementation.
# Retain the base image's non-root user, startup script, and HSM support.
COPY --chown=1001:1001 certify-service/target/certify-service-${CERTIFY_VERSION}.jar /home/inji/certify-service.jar
COPY --chown=1001:1001 dmt-dataprovider-plugin/target/dmt-dataprovider-plugin-${CERTIFY_VERSION}.jar /home/inji/additional_jars/dmt-dataprovider-plugin.jar

# Production settings are supplied through Spring environment variables,
# mounted configuration files, or the configured Spring Cloud Config server.
CMD ["java", "-Dloader.path=/home/inji/additional_jars/", "-jar", "/home/inji/certify-service.jar"]
