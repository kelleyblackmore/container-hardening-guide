# 13. Multi-Stage Builds — One Dockerfile, Many `FROM`s

The highest-leverage hardening technique available to you, and it costs one
extra `FROM` line.

Serves **§2.12** (only essential capabilities), **§2.8** (minimal layers), and
**§2.9** (no confidential data in the image).

```bash
make compare-stages     # build both and print the table below from real output
```

---

## 13.1 The mechanic

A Dockerfile may contain **more than one `FROM`**. Each one starts a new,
independent stage with its own base image and its own filesystem. Stages can be
named with `AS`, and a later stage can reach back into an earlier one with
`COPY --from=<stage>`.

```dockerfile
FROM golang:1.26-bookworm AS build      # <- stage 0: everything you need to BUILD
WORKDIR /src
COPY app/ ./
RUN go build -o /out/helloctr .

FROM registry.access.redhat.com/ubi9/ubi:9.6    # <- stage 1: everything you need to RUN
COPY --from=build /out/helloctr /app/helloctr
ENTRYPOINT ["/app/helloctr"]
```

**Only the last stage becomes the image.** Everything in `build` — the compiler,
the linker, the module cache, git, the headers, the source — is used to produce
`/out/helloctr` and is then discarded. It never appears in a layer, never
appears in the manifest, and never gets pulled by anyone.

The mental model that makes this click: the build stage is a **scratch space**,
not a parent. It is not a lower layer of the final image. The only thing that
crosses the boundary is what you explicitly `COPY --from`.

```
  ┌──────────────────────────────────────┐
  │  STAGE 0 "build"                     │
  │  golang:1.26-bookworm  (1.22 GB)     │
  │                                      │
  │  compiler, linker, assembler,        │  ─┐
  │  module cache, git, curl, headers,   │   │  DISCARDED
  │  YOUR SOURCE CODE                    │   │  never in the image
  │                                      │  ─┘
  │              /out/helloctr  ─────────┼───┐
  └──────────────────────────────────────┘   │  the only thing that crosses
                                             ▼
  ┌──────────────────────────────────────────────────┐
  │  STAGE 1  (this one becomes the image)           │
  │  ubi9/ubi:9.6                                    │
  │  patched OS + hardening + /app/helloctr          │
  └──────────────────────────────────────────────────┘
```

---

## 13.2 The same application, measured both ways

[`examples/single-stage/Dockerfile`](../examples/single-stage/Dockerfile) builds
the **exact same application from the exact same source** in one stage.
[`examples/hardened/Dockerfile`](../examples/hardened/Dockerfile) uses two.

| | single-stage | two-stage | |
|---|---|---|---|
| **Image size** | 1.35 GB / 926 MB | 581 MB / 396 MB | **≈2.3×** |
| Layers | 12 | 8 | |
| OS packages | 205 (dpkg) | 188 (rpm) | |
| `go`, `gcc`, `git` in the image | **yes** | no | |
| Application source in the image | **yes**, `/src` | no | |
| **Fixable HIGH/CRITICAL CVEs** | **12** | **0** | |
| Go binaries Trivy has to scan | **11** | 1 | |
| Runtime binary sha256 | `963e35a7c6…` | `963e35a7c6…` | **identical** |

That last row is the argument in one line. **The thing that runs is byte-for-byte
the same binary.** Everything in the other rows is packaging you chose to ship,
not capability you gained.

> **Why two size figures.** The first is Docker Desktop with buildx (which adds
> a manifest list and attestation manifests, inflating what `docker images`
> reports); the second is the GitHub Actions runner. Absolute sizes move with
> the builder, the exporter, and the base image of the week — **the ratio is the
> stable part**, and it was 2.3× in both environments.
>
> Do not trust the numbers in this table, including when they are right. Run
> `make compare-stages` and read your own, or open the *multi-stage comparison*
> job summary on any CI run, which regenerates the whole table from live images.
> The CI job also asserts the claims that must not drift: the single-stage image
> must be larger, it must contain the toolchain, and the hardened image must
> contain neither the toolchain nor the source.

Three of these rows deserve a closer look.

### "Go binaries Trivy has to scan: 11"

In the single-stage image the scanner's target list looks like this:

```
│ usr/local/bin/helloctr                        │ gobinary │ 0 │   <- your app
│ usr/local/go/bin/go                           │ gobinary │ 0 │
│ usr/local/go/bin/gofmt                        │ gobinary │ 0 │
│ usr/local/go/pkg/tool/linux_amd64/asm         │ gobinary │ 0 │
│ usr/local/go/pkg/tool/linux_amd64/cgo         │ gobinary │ 0 │
│ usr/local/go/pkg/tool/linux_amd64/compile     │ gobinary │ 0 │
│ usr/local/go/pkg/tool/linux_amd64/link        │ gobinary │ 0 │
│ ...                                                           │
```

One of those is your application. The other ten are the compiler. They read `0`
today because the toolchain is current — the moment a Go release fixes a stdlib
CVE, every one of them lights up, and you get to explain to somebody why your
web service has findings in its assembler.

### "OS packages: 205 vs 188" — why that row is nearly useless

Look at how little the package count moves: 205 against 188, while the image
itself is 2.3× larger. If you were watching package count as your hardening
metric, you would conclude the two images are about the same.

They are not. **The Go toolchain is not a dpkg package.** It is unpacked into
`/usr/local/go` by the official image, outside the package manager entirely.
Roughly 700 MB of compiler, linker, and standard library source arrives without
incrementing a counter that a package-manager-based inventory can see.

Worth internalising, because it generalises well beyond Go:

- A **package count** only counts what the package manager installed.
- An **SBOM** built purely from the package database inherits the same blind
  spot. This is why Syft and Trivy also fingerprint binaries by their embedded
  metadata — it is how the toolchain shows up as those 11 `gobinary` targets
  above, and how the Go stdlib CVEs get found at all.
- Anything installed by `curl | tar -x`, `make install`, a language version
  manager, or a vendored `node_modules` is in the same category: present,
  executable, and invisible to `rpm -qa`.

Size and the actual file listing tell you more than the package count does.

### "Fixable HIGH/CRITICAL: 12 vs 0"

Both images were built minutes apart from the same source. The 12 findings are
entirely in the Debian userland that `golang:1.26-bookworm` carries and the
application does not use. They are real CVEs in real packages that are really
present — a scanner is not wrong to report them, and an assessor is not wrong to
ask about them. They exist because of a packaging decision.

---

### No tool tells you to do this

Worth trying, because it reframes what linters are for:

```bash
hadolint --config .hadolint.yaml examples/single-stage/Dockerfile   # exits 0
```

The single-stage Dockerfile **passes hadolint cleanly**. It has a `USER`, a
tagged base from an allowed registry, a `HEALTHCHECK`, an exec-form
`ENTRYPOINT`, no `ADD`, no embedded secrets. Every rule satisfied. And it is
2.3x the size of the hardened image, with a compiler in it.

There is no `DL####` for "you shipped your build environment", because it is not
a property of any single instruction — it is the shape of the whole file. Same
for Trivy and Grype: they will faithfully report the 12 CVEs without ever
suggesting that the packages carrying them did not need to be there.

The decision is architectural, it is made in the first thirty seconds of writing
the Dockerfile, and no scanner in your pipeline will prompt you to make it.

---

## 13.3 Reading the reference implementation

[`examples/hardened/Dockerfile`](../examples/hardened/Dockerfile), condensed to
its structure:

```dockerfile
ARG BUILDER_IMAGE=docker.io/library/golang:1.26-bookworm
ARG RUNTIME_IMAGE=registry.access.redhat.com/ubi9/ubi:9.6

# ---------- STAGE 1: BUILD ----------
FROM ${BUILDER_IMAGE} AS build
WORKDIR /src
COPY app/go.mod ./
COPY app/main.go ./
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS="-trimpath"
RUN set -eux; \
    go vet ./...; \
    go build -ldflags="-s -w" -o /out/helloctr .; \
    test -x /out/helloctr

# ---------- STAGE 2: RUNTIME ----------
FROM ${RUNTIME_IMAGE}
...patch, harden, strip setuid, create the non-root user...
COPY --from=build --chown=1001:1001 --chmod=0555 /out/helloctr /app/helloctr
USER 1001:1001
ENTRYPOINT ["/app/helloctr"]
```

Points worth noticing:

**`ARG` before the first `FROM` is global.** Declared there, it is usable in
every `FROM` line in the file. Declared inside a stage, it is scoped to that
stage — which is why the runtime stage re-declares `ARG APP_UID` even though it
was set at the top.

**`AS build` names the stage.** You can also reference stages by index
(`COPY --from=0`), which works and is unreadable. Name them.

**`CGO_ENABLED=0` is what makes the boundary clean.** A statically linked binary
has no shared-library dependency on the build image's glibc, so it runs on any
base. If you build with cgo, the runtime stage must supply a compatible libc —
that is the usual cause of `no such file or directory` when executing a binary
that visibly exists (the *interpreter* is missing, not the file).

**`--chown` and `--chmod` on the `COPY`.** Doing it inline avoids a follow-up
`RUN chown` that would duplicate the entire binary in another layer.

**The `COPY --from` is the last content instruction.** The binary is the most
volatile thing in the image, so putting it last means a code change reuses every
layer above it.

---

## 13.4 Beyond two stages

Nothing limits you to two. Stages are cheap — they are just names.

### A test stage that gates the build

```dockerfile
FROM golang:1.26 AS build
WORKDIR /src
COPY app/ ./
RUN go build -o /out/app .

FROM build AS test
RUN go vet ./... && go test -race -cover ./...

FROM ubi9/ubi:9.6 AS runtime
COPY --from=build /out/app /app/app
```

`FROM build AS test` starts a stage *from another stage* — it inherits `build`'s
filesystem. Note that BuildKit only builds stages the target depends on, so
`runtime` does **not** pull in `test`. Run tests explicitly:

```bash
docker build --target test .      # fails the build if the tests fail
docker build --target runtime .   # the shipped image
```

`--target` is also how you get a debug variant without a second Dockerfile:

```dockerfile
FROM runtime AS debug
USER 0
RUN dnf -y install procps-ng strace gdb
USER 1001
```
`docker build --target debug` when you need it. It is never what gets published,
because it is not the last stage.

### A dependency stage, so the cache does the right thing

```dockerfile
FROM node:22 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev            # <- only re-runs when the lockfile changes

FROM node:22 AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12
COPY --from=deps  /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
CMD ["dist/server.js"]
```

Two things happen here. The dependency install is cached against the lockfile
rather than the source, so editing a `.ts` file does not re-run `npm ci`. And
`--omit=dev` means the runtime gets production dependencies only — the
TypeScript compiler, the test runner, and the linter stay in `build`.

### Copying from an image you never build

`--from` also accepts an image reference, which is a tidy way to pull one
binary out of a published image without installing anything:

```dockerfile
COPY --from=ghcr.io/org/tools:1.4 /usr/bin/migrate /usr/local/bin/migrate
COPY --from=cosign/cosign:v2 /ko-app/cosign /usr/local/bin/cosign
```

Treat that source image with the same suspicion as a `FROM` — it is a supply
chain input (§2.14, §2.17). Pin it by digest.

### Stages build in parallel

BuildKit builds the stage dependency graph, not a list. Independent stages run
concurrently:

```dockerfile
FROM golang:1.26 AS build-api      # ─┐
...                                #  │ these two build at the same time
FROM node:22    AS build-ui        # ─┘
...
FROM ubi9/ubi:9.6
COPY --from=build-api /out/api  /app/api
COPY --from=build-ui  /out/dist /app/static
```

---

## 13.5 The pattern in other languages

The Go example is the easiest case, because the output is one static file. The
principle holds everywhere; what crosses the boundary just differs.

| Language | Build stage produces | Runtime stage needs |
|---|---|---|
| **Go / Rust** | one static binary | nothing — `scratch` or a minimal base works |
| **Java** | a `.jar`, or a `jlink` runtime image | a JRE, not a JDK — no compiler, no `jmap`, no `jstack` |
| **Node** | `dist/` + production `node_modules` | the node runtime, no `devDependencies`, no source |
| **Python** | a wheel or a populated venv | the interpreter, no `gcc`, no `-dev` headers |
| **.NET** | `dotnet publish` output | the ASP.NET runtime image, not the SDK |
| **C/C++** | a linked binary | the runtime libs, no headers, no toolchain |

**Python**, the one people get wrong most often, because `pip install` frequently
needs a compiler for packages with native extensions — and then the compiler
stays:

```dockerfile
FROM python:3.13-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

FROM python:3.13-slim
COPY --from=build /opt/venv /opt/venv      # <- the venv crosses; gcc does not
ENV PATH="/opt/venv/bin:$PATH"
USER 1001
CMD ["python", "-m", "myapp"]
```

The venv is the artifact. `build-essential` and `libpq-dev` — hundreds of
megabytes and a large share of your CVE report — stay behind.

**Java**, where the win is the JDK-to-JRE step:

```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS build
COPY pom.xml .
RUN mvn -B dependency:go-offline          # cached against pom.xml
COPY src ./src
RUN mvn -B package -DskipTests=false

FROM eclipse-temurin:21-jre               # JRE, not JDK
COPY --from=build /target/app.jar /app/app.jar
USER 1001
ENTRYPOINT ["java","-jar","/app/app.jar"]
```

Shipping a JDK to production hands an attacker `javac`, plus `jcmd`, `jmap`, and
`jstack` — which attach to a running JVM and dump its heap, including whatever
credentials it is holding.

---

## 13.6 What multi-stage does *not* fix

It is a strong technique with a specific scope. Being clear about the edges
matters more than the enthusiasm.

- **It does not harden the runtime base.** A 25 MB base image full of unpatched
  packages is still unpatched. You still need §2.8 patching, §2.3 setuid
  removal, §2.2 the non-root user. Multi-stage removes the *build* surface; it
  does nothing about the *runtime* surface.
- **It does not hide build-time secrets.** `ARG GITHUB_TOKEN` in a discarded
  stage is genuinely gone from the final image, but a secret that reaches a
  layer of the *final* stage is still there, and the build cache on your CI
  runner holds the discarded stage's layers regardless. Use BuildKit secret
  mounts (§2.9, [docs/07](07-trufflehog.md)).
- **It does not make the base image approved.** Your builder image is a supply
  chain input under §2.17 even though it is discarded — it is what compiled your
  binary. In a DoD build the builder comes from Iron Bank too.
- **It does not patch the toolchain.** For compiled languages the stdlib is
  linked *into* the binary. The Go toolchain leaves the image; the Go standard
  library does not. This is not theoretical — this repository shipped a CRITICAL
  `crypto/tls` finding in a one-file image because the builder was pinned to Go
  1.23. Track the builder version.
- **It does not reduce the runtime's own dependencies.** If your app needs
  ImageMagick at runtime, ImageMagick ships. Multi-stage only removes what is
  needed to *build*.

---

## 13.7 A trap the numbers above exposed

The hardened image measures **581 MB**, on a **310 MB** base. Where did 271 MB
come from, when the only thing added is a 5 MB binary?

The `dnf upgrade` layer. Upgrading a package writes the **new** version's files
into the new layer; the **old** version's files are still sitting in the base
layer underneath, hidden but present and still transferred on every pull. Upgrade
most of the distribution and you approximately double the image.

This is the same mechanic as [docs/01 §1.3](01-anatomy-of-a-container-image.md)
— deleting or replacing a file in a later layer does not reclaim its bytes — and
it is the part of §2.8 that bites even when you have done the `&& dnf clean all`
correctly.

What actually helps, in order of preference:

1. **Start from a base that is already current.** Rebuild against the new UBI
   minor when Red Hat publishes it, so `upgrade` has little to do. This is the
   real fix and it is a scheduling problem, not a Dockerfile problem.
2. **Use a smaller runtime base** — `ubi9-minimal` (~90 MB) has far less to
   upgrade. Weigh it against the STIG-scannability trade-off in
   [docs/02](02-layer-by-layer-hardening.md).
3. **Flatten deliberately** — `docker build --squash`, or `FROM scratch` +
   `COPY --from`, collapses the duplication. It also destroys layer sharing
   between images and makes the history unreadable, so it is a last resort, not
   a default.

Note the direction of the trade: this is a *size* problem, not a *security*
problem. The superseded files are shadowed and cannot be executed. The reason to
care is pull time, storage, and the fact that a 581 MB image invites questions
about what is in it.

---

## 13.8 Which requirements this serves

| § | Requirement | How multi-stage serves it |
|---|---|---|
| 2.12 | Only essential capabilities | the compiler, linker, package manager, and fetch tools used to build never reach the image |
| 2.8 | Minimal cached layers | build-time intermediates cannot accumulate in the shipped image — they are in a different stage |
| 2.9 | No confidential data in the build | source, `.git`, build args, and credentials used during the build stay behind |
| 2.4 | Commands with known outcomes | `COPY --from=build` copies one named file from a stage, not an unpredictable download |
| 2.16 | STIG/SRG guidance | fewer packages means fewer applicable rules and a smaller waiver list |

---

## 13.9 Try it

```bash
make compare-stages
```

Builds both images from the same source and prints the size, layer count,
package count, toolchain presence, and CVE comparison. The single-stage image is
tagged `localhost/helloctr-singlestage:latest` and is safe to delete afterwards —
it is a measurement, not a deliverable.

---

**Back to:** [README](../README.md) ·
[2. Layer-by-Layer Hardening](02-layer-by-layer-hardening.md) ·
[8. Trivy and Grype](08-trivy-and-grype.md)
