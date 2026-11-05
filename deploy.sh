#!/bin/bash

#######################################
# cert-info Deployment Script
# Builds the image and (re)starts the certificate analysis API container.
#
# Environment variables:
#   TAG                    Image tag (default: latest)
#   CONTAINER_NAME         Container name (default: cert-info)
#   HOST_PORT              Port published on the host (default: 6010)
#   PORT                   Port the API listens on inside the container (default: 6010)
#   WORKERS                Number of uvicorn workers (default: 4)
#   REFRESH_TRUST_DATA     "true" to download the current Mozilla trust data
#                          (roots, distrust dates, preloaded intermediates, EV
#                          roots, OneCRL, CT logs, key pins) during the build, "false" to use the
#                          bundled files in src/trust/data (default: true)
#   CERTINFO_USER_AGENT    User-Agent of the HTTP requests cert-info makes (HTTPS
#                          probe, CRL/OCSP/AIA downloads), e.g. to point to a page
#                          about this deployment (default: cert-info/<version>
#                          (+https://github.com/dissect-project/cert_info))
#######################################

set -e  # Exit on error

# Configuration
IMAGE_NAME="cert-info"
TAG="${TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-cert-info}"
PORT="${PORT:-6010}"
HOST_PORT="${HOST_PORT:-6010}"
WORKERS="${WORKERS:-4}"
REFRESH_TRUST_DATA="${REFRESH_TRUST_DATA:-true}"
CERTINFO_USER_AGENT="${CERTINFO_USER_AGENT:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
        docker stop "${CONTAINER_NAME}" || true
        log_info "Removing existing container: ${CONTAINER_NAME}"
        docker rm "${CONTAINER_NAME}" || true
    fi
}

build_image() {
    local build_args=()
    if [ "${REFRESH_TRUST_DATA}" = "true" ]; then
        # A new value each day makes Docker re-run the download step
        build_args+=(--build-arg "REFRESH_TRUST_DATA=$(date -u +%Y-%m-%d)")
        log_info "Mozilla trust data will be refreshed during the build"
    else
        log_info "Using the bundled Mozilla trust data"
    fi
    log_info "Building Docker image: ${IMAGE_NAME}:${TAG}"
    docker build "${build_args[@]}" -t "${IMAGE_NAME}:${TAG}" .
    log_info "Image built successfully"
}

run_container() {
    log_info "Starting container: ${CONTAINER_NAME}"
    # Only passed when set, so the application's default applies otherwise
    local env_args=()
    if [ -n "${CERTINFO_USER_AGENT}" ]; then
        env_args+=(-e "CERTINFO_USER_AGENT=${CERTINFO_USER_AGENT}")
    fi
    docker run -d \
        --name "${CONTAINER_NAME}" \
        -p "${HOST_PORT}:${PORT}" \
        -e "PORT=${PORT}" \
        -e "WORKERS=${WORKERS}" \
        "${env_args[@]}" \
        --restart unless-stopped \
        "${IMAGE_NAME}:${TAG}"

    log_info "Container started successfully"
}

wait_for_health() {
    log_info "Waiting for service to be healthy..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "missing")
        case "${status}" in
            healthy)
                log_info "Service is healthy!"
                return 0
                ;;
            unhealthy)
                log_error "Service is unhealthy"
                docker logs --tail 50 "${CONTAINER_NAME}"
                return 1
                ;;
        esac
        if ! docker ps --filter "name=^${CONTAINER_NAME}$" --filter "status=running" -q | grep -q .; then
            log_error "Container stopped unexpectedly"
            docker logs --tail 50 "${CONTAINER_NAME}"
            return 1
        fi
        sleep 2
        attempt=$((attempt + 1))
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
    log_info "Workers: ${WORKERS}"
    log_info "User-Agent: ${CERTINFO_USER_AGENT:-default (cert-info/<version>)}"
    log_info "API Docs: http://localhost:${HOST_PORT}/docs"
    log_info "Example: curl 'http://localhost:${HOST_PORT}/certinfo/www.google.com?showcert=true'"
    echo ""
    log_info "To view logs: docker logs -f ${CONTAINER_NAME}"
    log_info "To stop: docker stop ${CONTAINER_NAME}"
    log_info "To restart: docker restart ${CONTAINER_NAME}"
    echo ""
}

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

main
