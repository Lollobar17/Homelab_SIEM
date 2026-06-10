# CI/CD Setup Guide — HomeLab SIEM

Complete guide to configure GitHub Secrets, connect the workflow to the K8s cluster,
and verify the automated pipeline end-to-end.

---

## Overview

The CI/CD pipeline consists of three jobs that run in cascade on every `git push` to `main`:

```
git push main
     │
     ▼
[Job 1 — CI]    Python lint (flake8) + smoke test
     │ (only if OK)
     ▼
[Job 2 — Build] Docker multi-arch build → push to Docker Hub
     │ (only if OK)
     ▼
[Job 3 — Deploy] kubectl set image → rolling update → health check
                          ↓ (on failure)
                   Automatic rollback
```

---

## 1. Required GitHub Secrets

Go to: `GitHub repo → Settings → Secrets and variables → Actions → New repository secret`

| Secret | Value | How to obtain |
|---|---|---|
| `DOCKERHUB_USERNAME` | Your Docker Hub username | e.g. `lollobar17` |
| `DOCKERHUB_TOKEN` | Docker Hub Access Token | See §2 |
| `KUBECONFIG_BASE64` | Cluster kubeconfig in base64 | See §3 |

---

## 2. Create a Docker Hub Access Token

1. Go to [hub.docker.com](https://hub.docker.com) → Account Settings → Security
2. Click **New Access Token** → name: `github-actions-siem`
3. Permissions: `Read & Write`
4. Copy the token → paste it as `DOCKERHUB_TOKEN` on GitHub

> Never use your Docker Hub password directly. Tokens are revocable.

---

## 3. Export the Cluster kubeconfig

### k3d (WSL2):

```bash
# Encode kubeconfig in base64
cat ~/.kube/config | base64 -w 0
```

Paste the output as `KUBECONFIG_BASE64` on GitHub.

---

## 4. Self-hosted Runner Setup

The deploy job runs on `self-hosted` — a runner installed on your local machine
that lets GitHub Actions communicate with the k3d cluster without exposing it to the internet.

### Install the runner

Go to: `GitHub repo → Settings → Actions → Runners → New self-hosted runner`

Select **Linux** and **x64**, then follow the three commands shown on the page.
When `./config.sh` asks:

| Question | Answer |
|---|---|
| Runner group | press Enter (default) |
| Runner name | `homelab-siem-runner` |
| Additional labels | press Enter (leave empty) |
| Work folder | press Enter (default `_work`) |

### Start the runner

```bash
cd ~/actions-runner
./run.sh
```

You should see:

```
√ Connected to GitHub
Listening for Jobs
```

> Keep this terminal open. The runner must stay active to receive jobs.

### Run as a systemd service (recommended for persistent use)

```bash
sudo ./svc.sh install
sudo ./svc.sh start
sudo ./svc.sh status
```

This keeps the runner active across WSL2 restarts without a dedicated terminal.

---

## 5. Verify the Pipeline

After configuration, trigger a test run:

```bash
git add .
git commit -m "ci: test pipeline"
git push origin main
```

Monitor on GitHub: `repo → Actions → CI/CD Pipeline`

Or via GitHub CLI:

```bash
gh run list --workflow=ci-cd.yml
gh run watch
```

### Expected output

```
✅ CI — Lint & Test          ~1 min
✅ Build & Push Docker Image  ~3 min
✅ Deploy → K8s Rolling Update ~2 min
```

Total: ~6 minutes from push to live deploy.

---

## 6. README Badges

Add to the top of `README.md`:

```markdown
![CI/CD](https://github.com/Lollobar17/Homelab_SIEM/actions/workflows/ci-cd.yml/badge.svg)
![Docker](https://img.shields.io/docker/v/lollobar17/homelab-siem?label=Docker%20Hub&style=flat)
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Job 3 never starts | Runner offline | Run `./run.sh` in `~/actions-runner` |
| `kubectl: command not found` | kubectl not in runner PATH | Add `export PATH=$PATH:/usr/local/bin` to `~/.bashrc` |
| `ImagePullBackOff` after deploy | Wrong digest or private image | Check `DOCKERHUB_TOKEN` secret is valid |
| Health check fails | App not ready in 30s | Increase `sleep 30` in the deploy job |
