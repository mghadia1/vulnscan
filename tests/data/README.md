# Test data

- `osv/*.json`: six real advisories, fetched from OSV's API
  (`https://api.osv.dev/v1/vulns/<id>`) on 2026-10-08, used as they are:
  GHSA-3h5v-q93c-6h6q (npm ws), PYSEC-2023-61 (PyPI django),
  GHSA-4v7x-pqxf-cx7m and GO-2024-2687 (the same Go bug in GitHub's and Go's
  databases), GHSA-223g-f5mq-gw33 (npm, a CVSS 4.0 vector only) and
  MAL-2022-2 (a malicious npm package). OSV data is published under
  CC-BY 4.0 by its sources (GitHub Advisory Database, PyPA, the Go
  vulnerability database, OpenSSF malicious packages).
- `sarif-schema-2.1.0.json`: the OASIS SARIF 2.1.0 schema, from
  `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`
  (SHA-256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e),
  to check VulnScan's SARIF against.
- `compose/*.yaml`: three of my own Compose files, copied on 2026-10-09
  from SurgiServe (`compose.yaml`), Gatekeeper (`compose.yaml`) and
  SyncBoard (`compose.replicas.yaml`): real files that use YAML anchors,
  aliases and merge keys, to check the YAML reader against PyYAML and the
  Compose rules against what they really say. Their passwords are local
  development defaults, and the rules are meant to report them.
- `buildkit/cases.json`: Dockerfiles with the hard cases of BuildKit's
  line handling, and BuildKit's own parse of each (keyword, first and last
  line, text, flags, JSON form, heredocs), recorded on 2026-10-09 with
  `scripts/buildkit_parse` (github.com/moby/buildkit v0.34.0), so that the
  tests check against BuildKit without needing Go.
