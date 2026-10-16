# osv-advisories

Security advisories for R packages, read once a day from [OSV](https://osv.dev), which publishes the [R Consortium advisory database](https://github.com/RConsortium/r-advisory-database). Part of [R Observatory](https://github.com/r-observatory).

Each run reads OSV's list of ecosystems and downloads the advisories of every ecosystem it wants that OSV lists: CRAN today, and Bioconductor once OSV publishes it. It works out which released CRAN versions each advisory affects by testing the advisory's ranges against every version CRAN has published (read from [cran-archive](https://github.com/r-observatory/cran-archive)), looks up the CVSS rating of each upstream CVE in OSV, and keeps a dated history of every change to an advisory.

## Output

`osv-advisories.db` on the rolling `current` release:

- `advisories`: one row per advisory, with its summary, dates, upstream ids, typed references and raw OSV JSON. `in_osv` is 0 for an advisory OSV no longer lists, which is kept rather than dropped. `first_seen` is the day this pipeline first saw it.
- `advisory_ranges`: the affected ranges exactly as OSV states them, one row per interval.
- `advisory_affected_versions`: one row per affected package version. `basis` says whether the range found it, OSV listed it by name, or both. `in_tarballs` is 0 for a version OSV lists that CRAN never published under that name.
- `advisory_upstream`: the CVSS vector of each upstream id, with the base score and rating for CVSS 3.x vectors. `lookup_status` is `ok`, `not_in_osv`, `failed`, or `failed_kept_previous` when a failed lookup kept the last run's row.
- `advisory_history`: one row per advisory per OSV `modified` value, with the day it was first seen. Never shrinks.
- `advisory_meta`: the fetch time, the ecosystems OSV listed, and the tool versions.

The release also carries `manifest.json`, the raw OSV export `osv-CRAN-all.zip`, and `ADVISORY-DATA-LICENSE.txt`.

A `backup-YYYY-MM` release holds a copy made by the first run of each month. Backups are never overwritten or pruned.

An upstream rating describes the upstream flaw, not how exposed the R package is. Nothing here adds ratings up into a figure for a package.

## When a run publishes nothing

- OSV's ecosystem list does not include CRAN, or the CRAN export cannot be downloaded.
- The previous release exists but cannot be downloaded. A repository with no release yet is a cold start.
- The cran-archive release cannot be downloaded.
- The run has fewer advisories than the previous manifest declared, or `advisory_history` would lose rows or its earliest row.
- The same advisory id appears in two ecosystems.

A failed upstream lookup never stops a run. It is counted in the manifest.

## Access

```sh
gh release download current --repo r-observatory/osv-advisories --pattern osv-advisories.db
```

```r
con <- DBI::dbConnect(RSQLite::SQLite(), "osv-advisories.db")
DBI::dbGetQuery(con, "SELECT package, version, advisory_id FROM advisory_affected_versions WHERE in_tarballs = 1")
```

```python
import sqlite3
con = sqlite3.connect("osv-advisories.db")
rows = con.execute("SELECT id, summary FROM advisories ORDER BY published DESC").fetchall()
```

## License

This repository is proprietary. Copyright (c) 2026 HJJB, LLC. All rights reserved; see [LICENSE](LICENSE). The advisory data comes from the R Consortium advisory database under the Apache License 2.0; see `ADVISORY-DATA-LICENSE.txt`.
