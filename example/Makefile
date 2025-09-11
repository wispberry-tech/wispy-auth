.PHONY: help install migrate run build clean test

# Default target
help: ## Show this help message
	@echo "Nucleus Auth Example - Available commands:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	go mod tidy

migrate: ## Run database migrations
	@echo "Running database migrations..."
	cd migrations && go run migrate.go

run: ## Start the development server
	@echo "Starting development server on :8080..."
	go run main.go handlers.go services.go

build: ## Build the application
	@echo "Building application..."
	go build -o bin/auth-server main.go handlers.go services.go

clean: ## Clean build artifacts
	rm -rf bin/

test: ## Run tests
	go test -v ./...

dev: install migrate run ## Setup and start development environment

docker-build: ## Build Docker image
	docker build -t nucleus-auth-example .

docker-run: ## Run with Docker
	docker run -p 8080:8080 --env-file .env nucleus-auth-example

setup-env: ## Copy environment file template
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file from template. Please edit it with your configuration."; \
	else \
		echo ".env file already exists."; \
	fi