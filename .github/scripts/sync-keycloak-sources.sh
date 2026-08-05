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
  mkdir -p src/main/java src/main/resources

  mvn clean install -Psync
  mv target/unpacked/* src/main/java/

  if  [ -d target/unpacked-resources -a ! -z "$(ls -A target/unpacked-resources/* 2>/dev/null)" ]
  then
    mv target/unpacked-resources/* src/main/resources/
  fi
  cd ..
}

# unpack sources without compiling, apply post-processing, then compile
function syncAndTransform() {
  MODULE=$1;
  TRANSFORM_FN=$2;
  echo_header "Syncing files in the module $MODULE";
  cd $MODULE

  rm -rf src/main/java/*
  rm -rf src/main/resources/*
  mkdir -p src/main/java src/main/resources

  mvn generate-sources -Psync
  mv target/unpacked/* src/main/java/

  if  [ -d target/unpacked-resources -a ! -z "$(ls -A target/unpacked-resources/* 2>/dev/null)" ]
  then
    mv target/unpacked-resources/* src/main/resources/
  fi

  $TRANSFORM_FN

  mvn clean install
  cd ..
}

# TODO: remove this revert once we accept the RawJsonValue breaking change (target: 27.x)
# revert RawJsonValue -> JsonNode in all affected files (dynamic, not a hardcoded list)
function revertRawJsonValue() {
  for file in $(grep -rl "org\.keycloak\.json\.RawJsonValue" src/main/java/ 2>/dev/null); do
      sed -i 's/import org.keycloak.json.RawJsonValue;/import com.fasterxml.jackson.databind.JsonNode;/g' "$file"
      sed -i 's/import org.keycloak.json.KeycloakJsonMapperFactory;/import org.keycloak.util.JsonSerialization;/g' "$file"
      sed -i 's/RawJsonValue/JsonNode/g' "$file"
      sed -i 's/KeycloakJsonMapperFactory\.mapper()/JsonSerialization.mapper/g' "$file"
  done
  rm -f src/main/java/org/keycloak/json/RawJsonValue.java
  rm -f src/main/java/org/keycloak/json/RawJsonValueSupport.java
  rm -f src/main/java/org/keycloak/json/Jackson2RawJsonValueSupport.java
  rm -f src/main/resources/META-INF/services/org.keycloak.json.RawJsonValueSupport

  remaining=$(grep -rl "RawJsonValue" src/main/java/ 2>/dev/null || true)
  if [ -n "$remaining" ]; then
      error "Found un-reverted RawJsonValue references in: $remaining"
  fi
}

# strip jackson 2 @JsonSerialize/@JsonDeserialize from meta-annotations;
# jackson 3 handles them via KeycloakAnnotationIntrospector3
function stripJackson2Annotations() {
  for file in src/main/java/org/keycloak/json/StringOrArray.java \
              src/main/java/org/keycloak/json/StringListMap.java \
              src/main/java/org/keycloak/json/MultivaluedHashMapValue.java \
              src/main/java/org/keycloak/json/ResourceTypeMap.java; do
      if [ -f "$file" ]; then
          sed -i '/import com\.fasterxml\.jackson\.databind/d' "$file"
          sed -i '/import org\.keycloak\.json\.\(StringOrArray\|StringListMap\|ResourceTypeMap\)Serializer/d' "$file"
          sed -i '/import org\.keycloak\.json\.\(StringOrArray\|StringListMap\|ResourceTypeMap\)Deserializer/d' "$file"
          sed -i '/import org\.keycloak\.representations\.workflows\.MultivaluedHashMapValue/d' "$file"
          sed -i '/@JsonSerialize/d' "$file"
          sed -i '/@JsonDeserialize/d' "$file"
      fi
  done
}

# Check if inside keycloak-client directory
if [[ ! $PWD == *keycloak-client ]]; then
  error "The script is supposed to be executed in the root of 'keycloak-client' repository";
fi;

syncAndTransform client-common-synced revertRawJsonValue
syncAndTransform client-common-synced-jackson3 stripJackson2Annotations
syncFiles admin-client
syncFiles admin-client-jackson3
syncFiles authz-client
