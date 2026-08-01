#!/usr/bin/env python3
"""
check-k8s-policy.py - assert the DISA section 3 deployment requirements.

Why write this when kube-linter, Polaris, Kyverno, and OPA/Gatekeeper exist?

  * As a TEACHING artifact it is explicit: every check below names the
    requirement it enforces, in the guide's own numbering, in about forty lines
    of readable code. You can see exactly what is being asserted and why.
  * As a CI GATE it does not drift: a third-party linter's default check set
    changes between releases, and a merge gate that changes behaviour when a
    tool auto-updates is a merge gate people learn to ignore.

For a real cluster, use an admission controller. A manifest check runs on the
manifests you remembered to put in the repo; an admission controller runs on
everything that is actually submitted to the API server, including what someone
applies by hand at 2am. Pod Security Admission (set in the Namespace labels of
k8s/deployment.yaml) plus Kyverno or Gatekeeper is the enforcing pair. This
script is the shift-left half that tells you before the PR merges.

Usage:  python3 scripts/check-k8s-policy.py k8s/
"""
from __future__ import annotations

import pathlib
import sys

import yaml

# Sensitive host paths from section 3.4. Mounting any of these hands the
# container some or all of the node.
SENSITIVE_HOST_PATHS = (
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/root",
    "/var/run/docker.sock", "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock", "/var/lib/kubelet", "/proc", "/sys",
    "/dev",
)

failures: list[str] = []
checked_pods = 0


def fail(req: str, where: str, msg: str) -> None:
    failures.append(f"[{req}] {where}: {msg}")


def check_pod_spec(spec: dict, where: str) -> None:
    """Assert requirements that live on the pod spec."""
    global checked_pods
    checked_pods += 1
    pod_sc = spec.get("securityContext") or {}

    # 3.10 - no access to the node's kernel namespaces.
    for field, req in (("hostPID", "3.10"), ("hostIPC", "3.10"), ("hostNetwork", "3.10")):
        if spec.get(field) is True:
            fail(req, where, f"{field}: true shares a node kernel namespace with the container")

    # 3.4 - sensitive host directories must not be mounted.
    for vol in spec.get("volumes") or []:
        hp = (vol.get("hostPath") or {}).get("path")
        if hp:
            fail("3.4", where, f"hostPath volume {vol.get('name')!r} mounts {hp}")
        # 3.1 - a container must not mount the platform's registry/API endpoint.
        if hp and hp.endswith(".sock"):
            fail("3.1", where, f"socket mount {hp} exposes a container/registry API")

    # 3.2 - system calls must be limited. seccomp may be set on the pod or on
    # each container; check the pod here and the container below.
    pod_seccomp = (pod_sc.get("seccompProfile") or {}).get("type")
    if pod_seccomp == "Unconfined":
        fail("3.2", where, "seccompProfile.type: Unconfined disables syscall filtering")

    # 3.1 - do not hand the workload a live API credential it does not need.
    if spec.get("automountServiceAccountToken") is not False:
        fail("3.1", where,
             "automountServiceAccountToken is not false; the pod receives a "
             "Kubernetes API token it probably does not need")

    for c in spec.get("containers") or []:
        check_container(c, f"{where}/{c.get('name', '?')}", pod_sc, pod_seccomp)


def check_container(c: dict, where: str, pod_sc: dict, pod_seccomp: str | None) -> None:
    sc = c.get("securityContext") or {}

    # 2.2 (enforced at deploy time) - must not run as root.
    run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    if run_as_non_root is not True:
        fail("2.2", where, "runAsNonRoot is not true")
    if run_as_user in (0, "0"):
        fail("2.2", where, "runAsUser is 0 (root)")

    # 2.3 (enforced at deploy time) - no privilege escalation.
    if sc.get("allowPrivilegeEscalation") is not False:
        fail("2.3", where, "allowPrivilegeEscalation is not false")
    if sc.get("privileged") is True:
        fail("2.3", where, "privileged: true disables container isolation")

    # 2.12 - only essential capabilities.
    dropped = [d.upper() for d in ((sc.get("capabilities") or {}).get("drop") or [])]
    if "ALL" not in dropped:
        fail("2.12", where, "capabilities.drop does not include ALL")
    added = [a.upper() for a in ((sc.get("capabilities") or {}).get("add") or [])]
    for cap in added:
        # Not automatically wrong - but each one needs a written justification,
        # so surface it rather than letting it pass silently.
        print(f"  NOTE  {where}: adds capability {cap} - justify this in the PR")

    # 3.7 - read-only root filesystem.
    if sc.get("readOnlyRootFilesystem") is not True:
        fail("3.7", where, "readOnlyRootFilesystem is not true")

    # 3.2 - seccomp, either inherited from the pod or set here.
    seccomp = (sc.get("seccompProfile") or {}).get("type") or pod_seccomp
    if seccomp not in ("RuntimeDefault", "Localhost"):
        fail("3.2", where, f"seccompProfile is {seccomp!r}; expected RuntimeDefault or Localhost")

    # 3.5 / 3.6 - resource limits and requests.
    res = c.get("resources") or {}
    for kind, req in (("limits", "3.5"), ("requests", "3.6")):
        block = res.get(kind) or {}
        for key in ("cpu", "memory"):
            if key not in block:
                fail(req, where, f"resources.{kind}.{key} is not set")

    # 3.8 / 3.9 - liveness and readiness probes.
    if not c.get("livenessProbe"):
        fail("3.8", where, "no livenessProbe")
    if not c.get("readinessProbe"):
        fail("3.9", where, "no readinessProbe")

    # 2.5 / 2.13 - non-privileged ports only.
    for p in c.get("ports") or []:
        cp = p.get("containerPort")
        if isinstance(cp, int) and cp < 1024:
            fail("2.5", where, f"containerPort {cp} is privileged (<1024)")

    # 2.14 / 2.15 - the image reference must identify specific bytes.
    image = c.get("image", "")
    if "@sha256:" not in image:
        tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""
        if not tag or tag == "latest":
            fail("2.14", where, f"image {image!r} has no tag or uses :latest")
        else:
            print(f"  NOTE  {where}: image {image!r} is tag-pinned; pin by digest for release")


def main(paths: list[str]) -> int:
    files: list[pathlib.Path] = []
    for p in paths:
        path = pathlib.Path(p)
        files.extend(sorted(path.rglob("*.y*ml")) if path.is_dir() else [path])

    for f in files:
        with f.open(encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind")
                name = (doc.get("metadata") or {}).get("name", "?")
                where = f"{f}:{kind}/{name}"
                if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"):
                    check_pod_spec((doc.get("spec", {}).get("template", {}) or {}).get("spec", {}) or {}, where)
                elif kind == "CronJob":
                    tmpl = (((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
                    check_pod_spec(tmpl.get("spec") or {}, where)
                elif kind == "Pod":
                    check_pod_spec(doc.get("spec") or {}, where)

    print(f"\nchecked {checked_pods} pod spec(s) across {len(files)} file(s)")
    if failures:
        print(f"\n{len(failures)} requirement violation(s):\n")
        for msg in failures:
            print(f"  FAIL  {msg}")
        print("\nRequirement text: docs/04-deployment-requirements.md")
        return 1
    print("all DISA section 3 assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["k8s/"]))
