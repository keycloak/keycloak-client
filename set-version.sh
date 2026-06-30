#!/bin/bash -e

NEW_VERSION=$1

# Maven
mvn versions:set -DnewVersion=$NEW_VERSION -DgenerateBackupPoms=false -DgroupId=org.keycloak* -DartifactId=*

echo "New Mvn Version: $NEW_VERSION" >&2
