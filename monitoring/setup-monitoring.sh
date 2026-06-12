#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
#  monitoring/setup-monitoring.sh
#  HomeLab SIEM — Prometheus + Grafana setup script
#
#  Usage: ./setup-monitoring.sh [install|status|teardown|restart-cluster]
#
#  ORDER:
#    1. Stop SIEM (free RAM)
#    2. Install Prometheus (wait for stable)
#    3. Install Grafana (wait for stable)
#    4. Restart SIEM
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SIEM_NS="homelab-siem"
MON_NS="monitoring"
CLUSTER_NAME="homelab-siem"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

wait_for_pods() {
    local ns=$1
    local label=$2
    local timeout=${3:-120}
    info "Waiting for pods ($label) to be ready..."
    kubectl wait pod \
        -n "$ns" \
        -l "$label" \
        --for=condition=Ready \
        --timeout="${timeout}s" 2>/dev/null || true
}

cmd_restart_cluster() {
    info "Recreating k3d cluster with all required ports..."
    warn "This will delete the current cluster. SIEM data (PVC) will be lost."
    read -r -p "Are you sure? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }

    k3d cluster delete "$CLUSTER_NAME" || true
    sleep 5

    k3d cluster create "$CLUSTER_NAME" \
        --port "30500:30500@loadbalancer" \
        --port "30514:30514@loadbalancer" \
        --port "30090:30090@loadbalancer" \
        --port "30300:30300@loadbalancer" \
        --agents 1

    info "Waiting for cluster to be ready..."
    sleep 30
    kubectl wait node --all --for=condition=Ready --timeout=120s
    success "Cluster ready with all ports mapped."
}

cmd_install() {
    info "=== HomeLab SIEM — Monitoring Stack Setup ==="
    echo ""

    # Step 1 — Stop SIEM to free RAM
    info "Step 1/4 — Scaling down SIEM to free RAM..."
    kubectl scale deployment homelab-siem -n "$SIEM_NS" --replicas=0 2>/dev/null || true
    sleep 10
    success "SIEM scaled down."

    # Step 2 — Install Prometheus
    info "Step 2/4 — Installing Prometheus..."
    kubectl create namespace "$MON_NS" --dry-run=client -o yaml | kubectl apply -f -

    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
    helm repo update

    helm upgrade --install prometheus prometheus-community/prometheus \
        --namespace "$MON_NS" \
        --timeout 8m \
        --set server.service.type=NodePort \
        --set server.service.nodePort=30090 \
        --set server.retention=7d \
        --set server.resources.requests.memory=128Mi \
        --set server.resources.limits.memory=300Mi \
        --set server.resources.requests.cpu=100m \
        --set server.resources.limits.cpu=300m \
        --set alertmanager.enabled=false \
        --set prometheus-pushgateway.enabled=false \
        --set kube-state-metrics.enabled=true \
        --set kube-state-metrics.resources.requests.memory=32Mi \
        --set kube-state-metrics.resources.limits.memory=64Mi

    info "Waiting for Prometheus to stabilize (90s)..."
    sleep 90
    wait_for_pods "$MON_NS" "app.kubernetes.io/name=prometheus" 120
    success "Prometheus ready."

    # Step 3 — Install Grafana
    info "Step 3/4 — Installing Grafana..."

    helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
    helm repo update

    helm upgrade --install grafana grafana/grafana \
        --namespace "$MON_NS" \
        --timeout 8m \
        --set adminPassword=admin123 \
        --set service.type=NodePort \
        --set service.nodePort=30300 \
        --set resources.requests.memory=100Mi \
        --set resources.limits.memory=200Mi \
        --set resources.requests.cpu=50m \
        --set resources.limits.cpu=200m \
        --set persistence.enabled=false \
        --set grafana.ini.plugins.allow_loading_unsigned_plugins="" \
        --set "env.GF_INSTALL_PLUGINS="

    info "Waiting for Grafana to stabilize (90s)..."
    sleep 90
    wait_for_pods "$MON_NS" "app.kubernetes.io/name=grafana" 120
    success "Grafana ready."

    # Step 4 — Restart SIEM
    info "Step 4/4 — Restarting SIEM..."
    kubectl scale deployment homelab-siem -n "$SIEM_NS" --replicas=1
    wait_for_pods "$SIEM_NS" "app=homelab-siem" 120
    success "SIEM restarted."

    echo ""
    success "=== Monitoring stack ready ==="
    cmd_status
}

cmd_status() {
    echo ""
    info "=== Pod Status ==="
    kubectl get pods -n "$MON_NS"
    echo ""
    info "=== Resource Usage ==="
    kubectl top pods -n "$MON_NS" 2>/dev/null || echo "Metrics not available yet"
    echo ""
    success "Prometheus:  http://localhost:30090"
    success "Grafana:     http://localhost:30300  (admin / admin123)"
    success "SIEM:        http://localhost:30500"
}

cmd_teardown() {
    warn "This will remove Prometheus and Grafana."
    read -r -p "Are you sure? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }

    helm uninstall prometheus -n "$MON_NS" 2>/dev/null || true
    helm uninstall grafana -n "$MON_NS" 2>/dev/null || true
    kubectl delete namespace "$MON_NS" --ignore-not-found
    success "Monitoring stack removed."
}

case "${1:-help}" in
    install)         cmd_install ;;
    status)          cmd_status ;;
    teardown)        cmd_teardown ;;
    restart-cluster) cmd_restart_cluster ;;
    *)
        echo "HomeLab SIEM — Monitoring Setup"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  restart-cluster  Recreate k3d cluster with all ports (30500, 30514, 30090, 30300)"
        echo "  install          Install Prometheus + Grafana (stops SIEM temporarily)"
        echo "  status           Show pod status and access URLs"
        echo "  teardown         Remove monitoring stack"
        ;;
esac
