# Lab 7 — Submission

## Task 1

### Vulnerability counts by severity

| Severity | Count |
|----------|-------|
| CRITICAL | 10 |
| HIGH | 64 |
| **Total** | **74** |

Of the 74 HIGH+CRITICAL findings, **71 have a fix available** and **3 do not**.

### Comparison with Lab 4 (Grype)

| Tool | CRITICAL | HIGH | Total (HIGH+CRITICAL) |
|------|----------|------|----------------------|
| Grype (Lab 4) | 14 | 84 | 98 |
| Trivy (Lab 7) | 10 | 64 | 74 |

Grype found more because it also picks up GHSA advisory IDs alongside CVE IDs and matches the embedded Node.js binary as a separate component. Trivy focuses on OS packages and npm manifests, so it misses some advisories that Grype catches via the GitHub Advisory Database.

### Top 10 fixable findings

| Severity | CVE | Package | Installed → Fix |
|----------|-----|---------|-----------------|
| CRITICAL | CVE-2023-46233 | crypto-js | 3.3.0 → 4.2.0 |
| CRITICAL | CVE-2026-71851 | crypto-js | 3.3.0 → 4.0.0 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.1.0 → 4.2.2 |
| CRITICAL | CVE-2015-9235 | jsonwebtoken | 0.4.0 → 4.2.2 |
| CRITICAL | CVE-2019-10744 | lodash | 2.4.2 → 4.17.12 |
| CRITICAL | CVE-2026-59873 | tar | 4.4.19 → 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar | 6.2.1 → 7.5.19 |
| CRITICAL | CVE-2026-59873 | tar | 7.5.15 → 7.5.19 |
| HIGH | CVE-2026-14456 | libssl3t64 | 3.5.5-1~deb13u2 → 3.5.7-1~deb13u2 |
| HIGH | CVE-2026-45447 | libssl3t64 | 3.5.5-1~deb13u2 → 3.5.6-1~deb13u2 |

### Dockerfile findings

```
DS-0002 (HIGH)   Last USER command is 'root'
DS-0001 (MEDIUM) FROM node:latest — no tag pinned
DS-0004 (MEDIUM) EXPOSE 22
DS-0026 (LOW)    No HEALTHCHECK instruction
```

**What each lets an attacker do:**

- **DS-0002** — if anything in the container is compromised, the attacker already has root. In a misconfigured cluster without `runAsNonRoot`, a container escape gives root on the node too.
- **DS-0001** — `node:latest` can silently pull a different image on the next build. If the upstream image is ever poisoned or broken, you won't know which version you're running.
- **DS-0004** — exposing port 22 suggests SSH might run inside the container. Even if it doesn't now, it's a signal that the image was designed for direct shell access — the kind of access that bypasses all audit logs.
- **DS-0026** — without a healthcheck, the orchestrator can't tell whether the container has actually started correctly. A process that started and immediately broke looks healthy to Docker.

### Vulnerabilities with no fix available

3 of the 74 HIGH/CRITICAL findings have no released fix. For those, the options are: (1) add a network policy that restricts what the container can reach, so even if the vuln is exploited the blast radius is smaller; (2) note them in a risk register with a review date, so they don't disappear into noise; (3) check the upstream project — sometimes a patch exists as a commit but hasn't been released. For a manager asking why the count isn't zero: vulnerability counts never reach zero for a running application. The relevant question is whether the ones without fixes have compensating controls and whether the ones with fixes are on a remediation schedule.

---

## Task 2

### Namespace labels

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/warn: restricted
pod-security.kubernetes.io/audit: restricted
```

### securityContext blocks

**Pod-level:**
```yaml
runAsNonRoot: true
runAsUser: 65532
seccompProfile:
  type: RuntimeDefault
```

**Container-level:**
```yaml
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
```

### Pod running — proof

```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-57977f5c76-l982n   1/1     Running   0          14s
```

User confirmed with:
```bash
kubectl -n juice-shop get pod -l app=juice-shop \
  -o jsonpath='{.items[0].spec.securityContext.runAsUser}'
# → 65532
```

### Trivy k8s summaries side by side

| Namespace | CRITICAL vulns | HIGH vulns | Misconfig HIGH |
|-----------|---------------|-----------|---------------|
| juice-plain | 10 | 64 | 3 |
| juice-shop | 10 | 64 | 1 |

**Why vulnerability counts are the same:** hardening the pod spec changes nothing about what's inside the image. Both deployments run the same digest — same npm packages, same OS libraries — so Trivy finds the same CVEs in both. Only rebuilding the image with updated packages changes vulnerability counts.

**Why misconfiguration counts differ:** the `juice-plain` deployment was created with a bare `kubectl create deployment` and has 3 High misconfigurations (no security context, privileged by default, root user). The `juice-shop` deployment sets `allowPrivilegeEscalation: false`, drops all capabilities, and runs as UID 65532, so only 1 High misconfiguration remains (there's always something — Trivy flags the image tag reference vs digest in juice-plain, and in juice-shop it picked up one remaining issue).

### One thing the `restricted` profile blocked, one voluntary control added

**Blocked:** the `restricted` profile rejected the pod when `allowPrivilegeEscalation` was not explicitly set to `false`. The admission webhook returned: `pods "juice-shop-..." is forbidden: violates PodSecurity "restricted"`. Setting it explicitly on the container securityContext fixed it.

**Added voluntarily:** `automountServiceAccountToken: false` on both the ServiceAccount and the pod spec. The `restricted` profile does not require this, but Juice Shop makes no API calls to the Kubernetes API server, so there's no reason to give the pod a token at all. Mounting a token that's never used is just an attack surface with no benefit.

---

## Bonus

### `docker diff` output (paths that matter)

```
A /juice-shop/data/juiceshop.sqlite
C /juice-shop/frontend/dist/frontend/index.html
A /juice-shop/frontend/dist/frontend/assets/public/images/ChatbotAvatar.png
A /juice-shop/frontend/dist/frontend/assets/public/images/hackingInstructor.png
A /juice-shop/frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
C /juice-shop/.well-known/csaf/provider-metadata.json
A /juice-shop/logs/access.log.2026-09-27
A /juice-shop/logs/audit.json
A /juice-shop/ftp/legal.md
A /juice-shop/i18n/*.json  (many locale files)
```

### Final volume layout

| mountPath | Volume | Why |
|-----------|--------|-----|
| `/juice-shop/data` | emptyDir (seeded) | App creates `juiceshop.sqlite` here; `data/static/challenges.yml` and other config files exist in the image and must be preserved — seeded by initContainer |
| `/juice-shop/frontend/dist/frontend` | emptyDir (seeded) | App modifies `index.html` at startup (`customizeApplication.js:103`); all Angular assets must be preserved — seeded by initContainer |
| `/juice-shop/.well-known` | emptyDir (seeded) | App rewrites `csaf/provider-metadata.json`; existing CSAF advisory files in the image must be preserved — seeded by initContainer |
| `/juice-shop/ftp` | emptyDir (seeded) | App writes `legal.md` at runtime; existing challenge files (acquisitions.md etc.) must be preserved — seeded by initContainer |
| `/juice-shop/i18n` | emptyDir (plain) | Only `.gitkeep` in the image; all locale JSON files are generated at runtime — no seeding needed |
| `/juice-shop/logs` | emptyDir (plain) | Empty in the image; log files created at runtime — no seeding needed |

The initContainer runs as the same image (`/nodejs/bin/node -e "copyDir(...)"`) and copies each seeded directory to a mount path under `/mnt/`, which the main container then mounts at the real paths.

### The directory that could not use an empty volume

`/juice-shop/data` is the interesting one. The first attempt was to mount an empty emptyDir there to allow the sqlite write — it crashed immediately because `data/static/challenges.yml` (and the other config/codefixes files in the image) were hidden. The app reads these at startup via `datacreator.js`. The fix was an initContainer that copies the full `data/` tree into the emptyDir volume before the main container starts, preserving the static files while making the directory writable.

### Proof

Pod ready with `readOnlyRootFilesystem: true`:
```
NAME                          READY   STATUS    RESTARTS   AGE
juice-shop-57977f5c76-l982n   1/1     Running   0
```

Container securityContext confirmed:
```json
{
  "allowPrivilegeEscalation": false,
  "capabilities": {"drop": ["ALL"]},
  "readOnlyRootFilesystem": true
}
```

HTTP 200 via port-forward:
```bash
kubectl -n juice-shop port-forward pod/juice-shop-57977f5c76-l982n 13001:3000
curl -sf -o /dev/null -w "%{http_code}" http://127.0.0.1:13001/
# → 200
```
