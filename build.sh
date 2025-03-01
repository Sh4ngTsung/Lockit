#!/bin/sh

# Run the tests
go test -v
if [ $? -ne 0 ]; then
    echo "Tests failed. Build aborted."
    exit 1
fi

# Compiling the binary
<<<<<<< HEAD
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o lockit main.go
=======
CGO_ENABLED=0 ; go build -trimpath -ldflags '-s -w -extldflags "-static"' -o lockit main.go
>>>>>>> 2b4498a (Update random nonce)

if [ $? -ne 0 ]; then
    echo "Build failed. Please check your code."
    exit 1
fi

# Remove debug symbols (optional, but recommended)
strip -s lockit

# Verify that the binary file was created correctly
if [ -f "./lockit" ]; then
    echo "Build successful! Run './lockit' to start."
else
    echo "Build failed. Binary not found."
    exit 1
fi
<<<<<<< HEAD
rm test_invalid_key.txt

=======
>>>>>>> 2b4498a (Update random nonce)
