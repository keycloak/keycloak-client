#!/bin/bash -e

CLIENT_REPOSITORY_ROOT_DIR=keycloak-client
KC_REPOSITORY_ROOT_DIR=keycloak

TARGET_REMOTE=upstream
CLIENT_REPO_DIR_PATH=$PWD

KC_TARGET_BRANCH=$1
KEYCLOAK_SOURCES_DIR_PATH=$2
if [ "$KEYCLOAK_SOURCES_DIR_PATH" == "" ]; then
  KEYCLOAK_SOURCES_DIR_PATH=$CLIENT_REPO_DIR_PATH/../keycloak
fi
TARGET_REMOTE=$3
if [ "$TARGET_REMOTE" == "" ]; then
  TARGET_REMOTE=upstream
fi

function revert() {
  if [ -n "$KC_WORK_BRANCH" ]; then
    echo_header "Returning back to branch '$KC_WORK_BRANCH' in the keycloak repository";
    git checkout $KC_WORK_BRANCH;
  fi;

  echo "Returning back to directory $CLIENT_REPO_DIR_PATH";
  cd $CLIENT_REPO_DIR_PATH;
}

function echo_header() {
  echo ""
  echo "======================================================================="
  echo "$1"
  echo "-----------------------------------------------------------------------"
}

function error() {
  echo "======================================================================="
  echo "Error"
  echo "-----------------------------------------------------------------------"
  echo "$1"
  echo ""
  revert;
  exit 1
}

function checkChangesInCurrentBranch() {
  # Check if no changes or any untracked files in current keycloak-client directory
  REPO=$1;

  COUNT=$(git diff | wc -l)
  if [[ ! $COUNT == 0 ]]; then
    error "There are uncommited changes in the '$REPO' repository. Please commit (or revert) everything first before executing this script.";
  fi;
  COUNT=$(git status | grep "Untracked files" | wc -l)
  if [[ ! $COUNT == 0 ]]; then
    error "There are untracked files in the '$REPO' repository. Please commit everything first before executing this script.";
  fi;
}

function copyFiles() {
  TEMPLATE=$1;
  KC_FROM=$2
  KC_CLIENT_TO=$3
  echo_header "Copying files from '$KC_REPOSITORY_ROOT_DIR/$KC_FROM' to '$CLIENT_REPOSITORY_ROOT_DIR/$KC_CLIENT_TO' with the use of template '$TEMPLATE'";
  for I in $(cat $CLIENT_REPO_DIR_PATH/.github/copy_templates/$TEMPLATE); do
      FROM=$KEYCLOAK_SOURCES_DIR_PATH/$KC_FROM/$I;
      # Helper variable
      TT=$(echo $I | sed -r 's/\*/FFFFF/g');
      TO=$(echo $CLIENT_REPO_DIR_PATH/$KC_CLIENT_TO/$TT | awk '{split($0,a,"FFFFF"); print a[1]}')
      echo "Copying $FROM to $TO";
      cp -r $FROM $TO;
  done
}

# Check if inside keycloak-client directory
if [[ ! $CLIENT_REPO_DIR_PATH == *$CLIENT_REPOSITORY_ROOT_DIR ]]; then
  error "The script is supposed to be executed in the root of '$CLIENT_REPOSITORY_ROOT_DIR' repository";
fi;


# Check if no changes or any untracked files in current keycloak-client repository
checkChangesInCurrentBranch $CLIENT_REPOSITORY_ROOT_DIR

if [ "$KC_TARGET_BRANCH" == "" ]; then
  error "Usage: sync-keycloak-sources.sh <KEYCLOAK BRANCH> <KEYCLOAK SOURCES DIRECTORY> <TARGET REMOTE>
  KEYCLOAK SOURCES DIRECTORY is optional and by default it is '../keycloak'
  TARGET REMOTE is optional and points to the reference of the repository (output of 'git remote' referencing repository). Default value is 'upstream'"
fi

if [ -d "$KEYCLOAK_SOURCES_DIR_PATH" ]; then
  echo_header "Using directory '$KEYCLOAK_SOURCES_DIR_PATH' with keycloak sources";
else
  error "Directory '$KEYCLOAK_SOURCES_DIR_PATH' does not exists";
fi

cd $KEYCLOAK_SOURCES_DIR_PATH;

# Check if keycloak repository is set to some real branch and there are no uncommited changes
KC_WORK_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$KC_WORK_BRANCH" == "HEAD" ]; then
  error "Repository '$KC_REPOSITORY_ROOT_DIR' is set to the detached HEAD. Please save all uncommited changes and use 'git checkout <some branch>' or 'git checkout -b <some branch>' in the $KC_REPOSITORY_ROOT_DIR repository before running this script";
fi

# Check if no changes or any untracked files in keycloak repository
checkChangesInCurrentBranch $KC_REPOSITORY_ROOT_DIR

# Checkout to the target branch in 'keycloak' repository
git checkout $TARGET_REMOTE/$KC_TARGET_BRANCH;

copyFiles common common client-common
copyFiles core core client-core
copyFiles admin-client integration/admin-client-jee integration/admin-client-jee
copyFiles admin-client integration/admin-client integration/admin-client

revert;