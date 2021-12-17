#!/bin/sh

PATH=/usr/lib/jvm/java-1.11.0-openjdk-amd64/bin:$PATH
export PATH

JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
export JAVA_HOME

echo $JAVA_HOME

exec ./gradlew "$@"
#exec java "--version"
