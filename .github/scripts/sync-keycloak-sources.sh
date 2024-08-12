#!/bin/bash -e

function echo_header() {
  echo ""
  echo "======================================================================="
  echo "$1"
  echo "-----------------------------------------------------------------------"
  echo ""
}

function error() {
  echo "======================================================================="
  echo "Error"
  echo "-----------------------------------------------------------------------"
  echo "$1"
  echo ""
  exit 1
}

function syncFiles() {
  MODULE=$1;
  echo_header "Syncing files in the module $MODULE";
  cd $MODULE

  # Remove the existing files before sync
  rm -rf src/main/java/*
  rm -rf src/main/resources/*

  mvn clean install -Psync
  mv target/unpacked/* src/main/java/

  if [ -d target/unpacked-resources ]; then
    mv target/unpacked-resources/* src/main/resources/
  fi
  cd ..
}

# Check if inside keycloak-client directory
if [[ ! $PWD == *keycloak-client ]]; then
  error "The script is supposed to be executed in the root of 'keycloak-client' repository";
fi;

syncFiles admin-client
syncFiles admin-client-jee
syncFiles authz-client
syncFiles policy-enforcer
