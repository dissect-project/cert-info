#!/bin/bash

#######################################
# cert-info Deployment Script
# Deploys the certificate analysis API service
#######################################

set -e  # Exit on error

# Configuration
IMAGE_NAME="cert-info"
TAG="${TAG:-latest}"
CONTAINER_NAME="cert-info"
PORT="${PORT:-6010}"
HOST_PORT="${HOST_PORT:-6010}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    
    log_info "Docker is available and running"
}

stop_existing_container() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Stopping existing container: ${CONTAINER_NAME}"
        docker stop ${CONTAINER_NAME} || true
        log_info "Removing existing container: ${CONTAINER_NAME}"
        docker rm ${CONTAINER_NAME} || true
    fi
}

build_image() {
    log_info "Building Docker image: ${IMAGE_NAME}:${TAG}"
    docker build -t ${IMAGE_NAME}:${TAG} .
    log_info "Image built successfully"
}

run_container() {
    log_info "Starting container: ${CONTAINER_NAME}"
    docker run -d \
        --name ${CONTAINER_NAME} \
        -p ${HOST_PORT}:${PORT} \
        --restart unless-stopped \
        ${IMAGE_NAME}:${TAG}
    
    log_info "Container started successfully"
    log_info "Service is accessible at: http://localhost:${HOST_PORT}"
}

wait_for_health() {
    log_info "Waiting for service to be healthy..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker inspect --format='{{.State.Health.Status}}' ${CONTAINER_NAME} 2>/dev/null | grep -q "healthy"; then
            log_info "Service is healthy!"
            return 0
        fi
        
        if docker ps --filter "name=${CONTAINER_NAME}" --filter "status=running" | grep -q ${CONTAINER_NAME}; then
            sleep 2
            attempt=$((attempt + 1))
        else
            log_error "Container stopped unexpectedly"
            docker logs ${CONTAINER_NAME}
            return 1
        fi
    done
    
    log_warn "Health check timeout. Container may still be starting..."
    return 0
}

show_info() {
    echo ""
    log_info "=== Deployment Summary ==="
    log_info "Container Name: ${CONTAINER_NAME}"
    log_info "Image: ${IMAGE_NAME}:${TAG}"
    log_info "Port Mapping: ${HOST_PORT}:${PORT}"
    log_info "API Docs: http://localhost:${HOST_PORT}/docs"
    log_info "Example: curl 'http://localhost:${HOST_PORT}/certinfo/www.google.com'"
    echo ""
    log_info "To view logs: docker logs -f ${CONTAINER_NAME}"
    log_info "To stop: docker stop ${CONTAINER_NAME}"
    log_info "To restart: docker restart ${CONTAINER_NAME}"
    echo ""
}

# Main deployment flow
main() {
    log_info "Starting deployment of ${IMAGE_NAME} service"
    
    check_docker
    stop_existing_container
    build_image
    run_container
    wait_for_health
    show_info
    
    log_info "Deployment completed successfully!"
}

# Run main function
main
