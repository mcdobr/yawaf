#!/bin/bash

DIR="$(dirname "$0")"

if cargo "$@"; then
    [ -d "$DIR/target/debug" ] && cp -r "$DIR/config" "$DIR/target/debug/config"
    [ -d "$DIR/target/release" ] && cp -r "$DIR/config" "$DIR/target/release/config"
fi
