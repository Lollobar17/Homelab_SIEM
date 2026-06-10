# Kubernetes Deployment — HomeLab SIEM

> Containerized deployment of HomeLab SIEM on k3d with enterprise-grade security,
> automated CI/CD via GitHub Actions, and verified self-healing.

---

## Stack

| Layer | Technology |
|---|---|
| Container runtime | Docker (multi-stage build) |
| Orchestration | Kubernetes via k3d |
| Image registry | Docker Hub (`lollobar17/homelab-siem`) |
| CI/CD | GitHub Actions |
| Persistence | PersistentVolumeClaim → SQLite (1 Gi) |
| Networking | NetworkPolicy — Zero Trust |
| Scaling | HorizontalPodAutoscaler |
| Observability | Liveness + Readiness + Startup probes |

---

## File Structure

```
k8s/
├── Dockerfile              # Multi-stage, non-root user, readOnlyRootFilesystem
├── docker-compose.yml      # Local dev stack for pre-K8s testing
├── deploy.sh               # Cluster automation script
├── README-K8s.md           # This file
└── manifests/
    ├── namespace.yaml      # Isolated homelab-siem namespace
    ├── configmap.yaml      # Runtime config and env injection
    ├── pvc.yaml            # SQLite storage (1 Gi, ReadWriteOnce)
    ├── deployment.yaml     # Pod spec with security context and probes
    ├── service.yaml        # NodePort :30500 (HTTP) + :30514 (syslog UDP)
    ├── networkpolicy.yaml  # Default-deny-all + minimal allow rules
    └── hpa.yaml            # Autoscaler (ready for PostgreSQL migration)
```

---

## Quick Start

### Prerequisites

- Docker Desktop running
- k3d installed:

```bash
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
```

### Full deploy

```bash
# Create cluster
k3d cluster create homelab-siem \
  --port "30500:30500@loadbalancer" \
  --port "30514:30514@loadbalancer" \
  --agents 1

# Build image + deploy to K8s
./k8s/deploy.sh all
```

Dashboard available at `http://localhost:30500`

---

## deploy.sh Commands

```bash
./k8s/deploy.sh build     # Build Docker image + import into cluster
./k8s/deploy.sh deploy    # Apply all K8s manifests
./k8s/deploy.sh all       # build + deploy in one shot
./k8s/deploy.sh status    # Show pods, services, PVC, HPA
./k8s/deploy.sh logs      # Stream container logs in real time
./k8s/deploy.sh teardown  # Delete all resources
```

---

## Security Features

| Feature | Detail |
|---|---|
| Non-root container | UID/GID 1000, user `siem` |
| Read-only filesystem | `readOnlyRootFilesystem: true` |
| No privilege escalation | `allowPrivilegeEscalation: false` |
| Capabilities | `CAP_ALL` dropped |
| NetworkPolicy | Default-deny-all, Zero Trust |
| Resource limits | CPU 500m / RAM 512Mi |

---

## CI/CD Pipeline

Every `git push` to `main` triggers automatically:

```
[1] Python lint (flake8) + smoke test
        ↓ (only if OK)
[2] Docker multi-arch build (amd64 + arm64) → push to Docker Hub
        ↓ (only if OK)
[3] kubectl set image → rolling update on K8s
        ↓ (on failure)
    Automatic rollback to previous version
```

Full CI/CD setup guide: `docs/SETUP-CICD.md`

---

## Endpoints

| URL | Description |
|---|---|
| `http://localhost:30500` | SIEM Dashboard |
| `http://localhost:30500/api/health` | Health check |
| `udp://localhost:30514` | Syslog ingestion |

---

## Useful kubectl Commands

```bash
# Full status
kubectl get pods,svc,pvc,hpa -n homelab-siem

# Stream logs
kubectl logs -n homelab-siem -l app=homelab-siem -f

# Force rollout after ConfigMap change
kubectl rollout restart deployment/homelab-siem -n homelab-siem

# Manual rollback
kubectl rollout undo deployment/homelab-siem -n homelab-siem

# Shell into container
kubectl exec -it -n homelab-siem \
  $(kubectl get pod -n homelab-siem -l app=homelab-siem -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/sh
```

---

## Future Roadmap

- [ ] Migrate SQLite → PostgreSQL (enables `replicas > 1`)
- [ ] Ingress with TLS (cert-manager + Let's Encrypt)
- [ ] Helm chart for parametrized distribution
- [ ] Prometheus + Grafana sidecar for K8s-native metrics
- [ ] Self-hosted runner as systemd service
