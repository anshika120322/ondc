.PHONY: help build test clean run-python run-java run-nodejs run-go run-php run-ruby report

help:
	@echo "ONDC Multi-Language Signature Test Suite"
	@echo ""
	@echo "Available commands:"
	@echo "  make build      - Build all Docker images"
	@echo "  make test       - Run all tests and generate report"
	@echo "  make clean      - Clean up test reports"
	@echo "  make run-python - Run Python tests only"
	@echo "  make run-java   - Run Java tests only"
	@echo "  make run-nodejs - Run Node.js tests only"
	@echo "  make run-go     - Run Go tests only"
	@echo "  make run-php    - Run PHP tests only"
	@echo "  make run-ruby   - Run Ruby tests only"
	@echo "  make report     - Generate HTML report from existing results"

build:
	@echo "Building Docker images..."
	docker-compose build

test: clean build
	@echo "Running all tests..."
	@./run-tests.sh

clean:
	@echo "Cleaning up test reports..."
	@rm -f reports/*.json reports/*.html
	@echo "✓ Clean complete"

run-python:
	@echo "Running Python tests..."
	docker-compose run --rm python-signature

run-java:
	@echo "Running Java tests..."
	docker-compose run --rm java-signature

run-nodejs:
	@echo "Running Node.js tests..."
	docker-compose run --rm nodejs-signature

run-go:
	@echo "Running Go tests..."
	docker-compose run --rm golang-signature

run-php:
	@echo "Running PHP tests..."
	docker-compose run --rm php-signature

run-ruby:
	@echo "Running Ruby tests..."
	docker-compose run --rm ruby-signature

report:
	@echo "Generating HTML report..."
	@python3 test-orchestrator/report_generator.py
	@echo "✓ Report generated: reports/compatibility-report.html"
	@if command -v open > /dev/null; then open reports/compatibility-report.html; fi
