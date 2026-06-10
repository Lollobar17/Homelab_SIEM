#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="homelab-siem"
IMAGE_NAME="lollobar17/homelab-siem"
IMAGE_TAG="latest"
MANIFESTS_DIR="$(dirname "$0")/manifests"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }

cmd_build() {
    info "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
    docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -f "$(dirname "$0")/Dockerfile" ..
    success "Image built."
    info "Importing image into k3d cluster..."
    k3d image import "${IMAGE_NAME}:${IMAGE_TAG}" -c homelab-siem
    success "Image imported."
}

cmd_deploy() {
    info "Deploying HomeLab SIEM to namespace: ${NAMESPACE}"
    kubectl apply -f "${MANIFESTS_DIR}/namespace.yaml"
    kubectl apply -f "${MANIFESTS_DIR}/configmap.yaml"
    kubectl apply -f "${MANIFESTS_DIR}/pvc.yaml"
    kubectl apply -f "${MANIFESTS_DIR}/networkpolicy.yaml"
    kubectl apply -f "${MANIFESTS_DIR}/deployment.yaml"
    kubectl apply -f "${MANIFESTS_DIR}/service.yaml"
    kubectl apply -f "${MANIFESTS_DIR}/hpa.yaml"
    info "Waiting for deployment to be ready..."
    kubectl rollout status deployment/homelab-siem \
        -n "${NAMESPACE}" --timeout=120s
    success "HomeLab SIEM deployed successfully!"
    cmd_status
}

cmd_status() {
    info "=== Cluster Status ==="
    kubectl get pods,svc,pvc,hpa -n "${NAMESPACE}"
    success "Dashboard: http://localhost:30500"
    success "API health: http://localhost:30500/api/health"
}

cmd_teardown() {
    warn "This will delete ALL SIEM resources."
    read -r -p "Are you sure? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
    kubectl delete namespace "${NAMESPACE}" --ignore-not-found
    success "Namespace ${NAMESPACE} deleted."
}

cmd_logs() {
    kubectl logs -n "${NAMESPACE}" -l app=homelab-siem --tail=100 -f
}

case "${1:-help}" in
    build)    cmd_build   ;;
    deploy)   cmd_deploy  ;;
    status)   cmd_status  ;;
    teardown) cmd_teardown ;;
    logs)     cmd_logs    ;;
    all)      cmd_build && cmd_deploy ;;
    *)
        echo "Usage: $0 <build|deploy|all|status|logs|teardown>"
        ;;
esac
