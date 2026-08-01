# 11. Approved Base Image Sources

> DISA Container Image Creation and Deployment Guide V2R0.6, Appendix A —
> DoD Base Container Image Approved Sources (DBCIAS)

> To ensure container base images are from approved sources, a container base
> image must be downloaded from a DBCIAS as a baseline.
>
> The following sources are currently approved and should be used in order of
> priority:
>
> - Iron Bank/DCAR (approved DoD-wide; **trusted**)
> - Product vendor proprietary repository (**untrusted**)
> - Docker Hub (**untrusted**)
> - Red Hat Container Repository (**untrusted**)

Read that list carefully: **only the first entry is marked trusted.** The other
three are *approved sources* that are *untrusted*, which means you may pull from
them and you must independently verify what you pulled — signature, digest, and
your own scan — before building on it.

---

## 11.1 Iron Bank / DCAR

Iron Bank is the DoD's hardened container repository, run by Platform One. DCAR
(DoD Centralized Artifact Repository) is the underlying registry.

- Registry: `registry1.dso.mil`
- Catalogue: <https://repo1.dso.mil/dsop> · <https://ironbank.dso.mil>

Images are built and scanned through the pipeline described in §4.3 of the
guide, and each one ships with its scan results, its findings whitelist, and its
justifications — the artifacts an assessor wants, already produced.

```dockerfile
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9@sha256:<digest>
```

```bash
docker login registry1.dso.mil        # requires a Platform One account
```

**What "hardened" gets you and what it does not.** An Iron Bank base image
arrives with its own STIG evaluation and an approved whitelist, which is a
genuine head start. It does not make *your* image compliant: the moment you add
a layer you own the result, and the requirements in
[docs/03](03-image-creation-requirements.md) apply to what you built, not to
what you started from.

This repository uses `registry.access.redhat.com` because it is public and
readers can run the examples. In a DoD build, the `FROM` lines and the
`allowed-registries` list in [`.hadolint.yaml`](../.hadolint.yaml) become one
entry: `registry1.dso.mil`.

---

## 11.2 The untrusted sources, in priority order

### Product vendor proprietary repository
The vendor's own registry — `registry.redhat.io`, Oracle, Elastic, MongoDB.
Closest to the source, usually signed, usually the fastest to publish patches.

### Docker Hub
Enormous and almost entirely unvetted. If you must:
- **Official Images** and **Verified Publisher** content only — never a random
  user namespace;
- pin by digest;
- expect rate limits to become a build dependency you did not plan for.

### Red Hat Container Repository
`registry.access.redhat.com` — UBI images, publicly redistributable, signed by
Red Hat, with a published health index. UBI is the practical default for
RHEL-family work outside Iron Bank, which is why this repo uses it.

---

## 11.3 Verify, regardless of source

Everything below applies even to Iron Bank. Trust the source; verify the bytes.

```bash
# 1. Resolve tag -> digest, and pin the digest
skopeo inspect docker://registry.access.redhat.com/ubi9/ubi:9.6 | jq -r '.Digest'
make digests

# 2. Verify the signature
cosign verify <image> \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
podman pull --signature-policy /etc/containers/policy.json <image>

# 3. Scan it yourself before you build on it
trivy image --severity HIGH,CRITICAL <image>
grype <image> --only-fixed

# 4. Look at what is actually in it
syft <image> -o table
docker run --rm --entrypoint /bin/bash <image> -c 'rpm -qa | wc -l'
```

---

## 11.4 Enforce it, do not just document it

Three layers, each catching what the previous one missed:

**Lint time** — [`.hadolint.yaml`](../.hadolint.yaml):
```yaml
allowed-registries:
  - registry1.dso.mil
```
DL3026 fails the build on a `FROM` outside the list.

**Build time** — an internal pull-through proxy (Harbor, Artifactory, Nexus) as
the *only* registry the builders can reach. If the network cannot resolve Docker
Hub, no policy document is required.

**Admission time** — reject images from unapproved registries, and images
without a valid signature, at the API server:
```yaml
# Kyverno
- name: restrict-registries
  match: { any: [{ resources: { kinds: [Pod] } }] }
  validate:
    message: "Images must come from registry1.dso.mil"
    pattern:
      spec:
        containers:
          - image: "registry1.dso.mil/*"
```

Admission is the one that actually holds. The first two are conveniences that
tell a developer early; only the third stops something running.

---

## 11.5 Related references

| Document | Why |
|---|---|
| [NIST SP 800-190](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf) | Application Container Security Guide — cited by §1.2.1 |
| [NIST SP 800-52r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf) | TLS selection and configuration — cited by §2.7 |
| [DoD Enterprise DevSecOps Reference Design](https://dodcio.defense.gov/Library/) | cited by §1.2.3 and §4 |
| [DISA STIGs](https://public.cyber.mil/stigs/) | the STIGs and SRGs themselves |
| [DISA SCAP content](https://public.cyber.mil/stigs/scap/) | the benchmark an assessor is likely to run |
| [SCAP Security Guide](https://github.com/ComplianceAsCode/content) | the SSG content used by `make stig` |
| [OCI Image Specification](https://github.com/opencontainers/image-spec) | the manifest/config/layer format from [docs/01](01-anatomy-of-a-container-image.md) |
| [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) | the `restricted` profile used in [docs/04](04-deployment-requirements.md) |

---

**Next:** [12. Waivers and POA&Ms](12-waivers-and-poam.md)
