# Reference

The source document this repository implements.

| File | What it is |
|---|---|
| [`DISA-Container-Image-Creation-and-Deployment-Guide-V2R0.6.md`](DISA-Container-Image-Creation-and-Deployment-Guide-V2R0.6.md) | Text transcription of the DISA guide, kept here so every `[2.x]` / `[3.x]` tag in this repo resolves to the words it came from |

## Provenance

**Container Image Creation and Deployment Guide**
Version 2, Release 0.6 — 02 November 2020
Developed by DISA for the DoD

> DISTRIBUTION – DISTRIBUTION STATEMENT A. Approved for public release.
> Distribution is unlimited. (November 2020).

A U.S. Government work, approved for public release, which is why it can be
redistributed here. It is **not** covered by this repository's MIT licence —
that applies to the code and documentation written for this project. The guide
is a separate work under its own distribution statement, reproduced unmodified.

## Why it is vendored

Every requirement tag in this repository — `[2.2]` in a Dockerfile comment,
`[3.7]` in a Kubernetes manifest, the CCIs in
[`docs/compliance-matrix.md`](../docs/compliance-matrix.md) — points at a section
of this document. Having it in the tree means a reader can check a claim against
the source without leaving the repo, and means the tags stay resolvable if the
copy you downloaded it from moves.

## Caveats

- **This is a text transcription, not the PDF.** It is faithful to the wording
  of the source, but it is a convenience copy. For anything that matters —
  an assessment, an audit, a dispute about interpretation — use the official
  document from [public.cyber.mil](https://public.cyber.mil/stigs/), not this
  file.
- **The eleven figures are not included.** The source has diagrams (container
  layers, the container platform, and the six Iron Bank pipeline stages) that
  are images in the PDF. Their captions are retained in place with a note, and
  where a figure carries information the text does not, this repository's own
  documentation says so in prose — see
  [docs/01](../docs/01-anatomy-of-a-container-image.md) for the layer model and
  [docs/09](../docs/09-devsecops-pipeline.md) for the pipeline stages.
- **V2R0.6 is from November 2020.** Container tooling has moved: Pod Security
  Policy became Pod Security Admission, Docker stopped being the default
  Kubernetes runtime, and Sigstore/cosign did not exist in its current form.
  The *requirements* still hold; some of the implementation advice reads as
  dated. Where this repository implements a requirement in a way the 2020 text
  would not have described, the reasoning is written into the relevant doc
  rather than silently substituted. Check
  [public.cyber.mil](https://public.cyber.mil/stigs/) for a newer release before
  citing a version in your own work.

## Related official sources

| Document | Link |
|---|---|
| DISA STIGs and SRGs | <https://public.cyber.mil/stigs/> |
| DISA SCAP benchmark content | <https://public.cyber.mil/stigs/scap/> |
| NIST SP 800-190, Application Container Security Guide (cited by §1.2.1) | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf> |
| NIST SP 800-52 Rev. 2, TLS guidelines (cited by §2.7) | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf> |
| DoD Enterprise DevSecOps Reference Design (cited by §1.2.3, §4) | <https://dodcio.defense.gov/Library/> |
| Iron Bank | <https://ironbank.dso.mil> |
