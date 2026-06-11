BINARY := auditor
BUILD_DIR := ./bin

.PHONY: build install test clean

build:
	go build -o $(BUILD_DIR)/$(BINARY) .

install:
	go install .

test:
	go test ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	go mod tidy
