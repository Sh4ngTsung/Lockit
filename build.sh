#!/bin/sh

go test -v
if [ $? -ne 0 ]; then
    echo "Tests failed. Build aborted."
    exit 1
fi

CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -extldflags "-static"' -o lockit main.go

if [ $? -ne 0 ]; then
    echo "Build failed. Please check your code."
    exit 1
fi

if command -v strip > /dev/null 2>&1; then
    strip -s lockit
    echo "Binary stripped successfully."
else
    echo "Warning: 'strip' is not installed on this system. Binary was not stripped."
fi

if [ -f "./lockit" ]; then
    echo "Build successful! Run './lockit' to start."
else
    echo "Build failed. Binary not found."
    exit 1
fi
