FROM mosipid/inji-certify:0.11.0

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

# copy all files under target/ to the plugins folder
COPY ./target/*.jar ${loader_path_env}
