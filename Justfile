IMAGE := "kuberhealthy/ssl-handshake-check"
TAG := "latest"

# Build the SSL handshake check container locally.
build:
	podman build -f Containerfile -t {{IMAGE}}:{{TAG}} .

# Run the unit tests for the SSL handshake check.
test:
	go test ./...

# Build the SSL handshake check binary locally.
binary:
	go build -o bin/ssl-handshake-check ./cmd/ssl-handshake-check
