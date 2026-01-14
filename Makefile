.PHONY: build test clean install run

build:
	go build -o idor-scan .

test:
	go test -v ./...

clean:
	rm -f idor-scan
	rm -rf reports/

install:
	go install .

run:
	go run . --collection examples/sample-collection.postman.json --users examples/users.json -v

fmt:
	go fmt ./...

lint:
	golangci-lint run

deps:
	go mod download
	go mod tidy

release:
	goreleaser release --clean
