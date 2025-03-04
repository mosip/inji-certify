FROM mosipdev/inji-certify:release-0.11.x

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

# copy all files under target/ to the plugins folder
COPY ./target/certify-plugins/*.jar ${loader_path_env}
