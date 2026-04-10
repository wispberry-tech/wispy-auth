#!/bin/bash

# Run all Go tests with race detection and coverage
go test -v -race -coverprofile=coverage.out ./... "$@"
