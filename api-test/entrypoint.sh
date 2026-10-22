#!/bin/bash

## Run automationtests
set +e
java -jar -Dmodules="$MODULES" -Denv.user="$ENV_USER" -Denv.endpoint="$ENV_ENDPOINT" -Denv.testLevel="$ENV_TESTLEVEL" -DuseCaseToExecute="$ENV_USECASE" apitest-injicertify-*-jar-with-dependencies.jar
JAVA_EXIT=$?

# Ensure report directory exists with at least a placeholder so artifact upload never gets empty
mkdir -p /home/inji/testng-report
if [ ! -f /home/inji/testng-report/index.html ] && [ -z "$(ls -A /home/inji/testng-report 2>/dev/null)" ]; then
    echo "<html><body><h1>Inji-Certify API Test Run</h1><p>Java process exited with code: $JAVA_EXIT. No TestNG report was generated — check apitest container logs for details.</p></body></html>" \
        > /home/inji/testng-report/index.html
fi

exit $JAVA_EXIT
