#!/usr/bin/env Rscript
# scripts/update.R: build osv-advisories.db from OSV.
#
# run_update(io, out_dir) takes an injectable io (see default_io() in io.R) so
# the whole run can be tested offline. It writes osv-advisories.db,
# manifest.json, the raw zip of every fetched ecosystem and the advisory data
# licence into out_dir, and stops with an error, writing nothing worth
# publishing, when a guard fails.
#
# Usage: Rscript scripts/update.R [out_dir]

options(timeout = 600)

suppressPackageStartupMessages({
  library(DBI)
  library(RSQLite)
  library(jsonlite)
})

.script_dir <- local({
  a <- commandArgs(FALSE)
  f <- sub("^--file=", "", grep("^--file=", a, value = TRUE))
  if (length(f) == 1L && nzchar(f)) dirname(normalizePath(f)) else "scripts"
})
if (!exists("expand_affected", mode = "function")) {
  for (f in c("config.R", "osv.R", "expand.R", "cvss.R", "state.R", "export.R", "io.R")) {
    source(file.path(.script_dir, f))
  }
}

iso <- function(t) format(t, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")

run_update <- function(io, out_dir, license_src = file.path(.script_dir, "..", LICENSE_ASSET)) {
  dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)
  now <- io$now()
  today <- format(now, "%Y-%m-%d", tz = "UTC")

  # 1. Which ecosystems OSV publishes. CRAN must be among them.
  listed <- parse_ecosystems(io$ecosystems())
  fetch <- ecosystems_to_fetch(listed)
  if (!"CRAN" %in% fetch) stop("OSV's ecosystems.txt does not list CRAN")

  # 2. The previous release. A failed download stops the run here.
  prev <- io$prev_state()
  if (!prev$status %in% c("ok", "cold_start")) stop("unexpected previous-release status: ", prev$status)
  prev_tables <- if (identical(prev$status, "ok")) read_prev_tables(prev$db) else list()
  prev_manifest <- if (identical(prev$status, "ok")) prev$manifest else NULL

  # 3. Parse every listed ecosystem's advisories.
  adv <- empty_advisories(); ranges <- NULL; listed_v <- NULL
  for (eco in fetch) {
    zip <- io$osv_zip(eco, file.path(out_dir, raw_zip_name(eco)))
    dir <- tempfile(paste0("osv-", eco, "-")); dir.create(dir)
    unzip_strict(zip, dir)
    items <- read_osv_dir(dir)
    adv <- rbind(adv, osv_advisories_df(items, eco))
    ranges <- rbind(ranges, osv_ranges_df(items, eco))
    listed_v <- rbind(listed_v, osv_listed_df(items, eco))
  }
  if (any(duplicated(adv$id))) stop("duplicate advisory ids across ecosystems")
  parsed_n <- nrow(adv)
  reasons <- parse_guard(prev_manifest, parsed_n)
  if (length(reasons)) stop("not publishing: ", paste(reasons, collapse = "; "))

  # 4. Expand CRAN ranges against every CRAN version ever published.
  versions <- io$archive_versions()
  withdrawn <- adv$id[!is.na(adv$withdrawn)]
  ex <- expand_affected(ranges[ranges$ecosystem %in% EXPAND_ECOSYSTEMS, , drop = FALSE],
                        listed_v[listed_v$ecosystem %in% EXPAND_ECOSYSTEMS, , drop = FALSE],
                        versions, withdrawn)
  affected_in_tarballs <- sum(ex$rows$in_tarballs == 1L)
  reasons <- versions_guard(prev_manifest, nrow(versions), affected_in_tarballs)
  if (length(reasons)) stop("not publishing: ", paste(reasons, collapse = "; "))

  # 5. Upstream severity. A failed lookup never blocks the run.
  ids <- upstream_ids(adv)
  lookups <- setNames(lapply(ids, function(id) {
    tryCatch(io$osv_vuln(id), error = function(e) list(status = "failed", record = NULL))
  }), ids)
  failed <- ids[vapply(lookups, function(l) identical(l$status, "failed"), logical(1))]
  upstream <- carry_upstream(prev_tables$advisory_upstream,
                             upstream_rows(adv, lookups, iso(now)), failed)

  # 6. History and carry forward, then the guards.
  history <- merge_history(prev_tables$advisory_history, adv, today)
  advisories <- carry_forward(prev_tables$advisories, adv, history)
  reasons <- publish_guard(prev_manifest, advisories, history)
  if (length(reasons)) stop("not publishing: ", paste(reasons, collapse = "; "))

  # 7. Write the database, the licence and the manifest.
  bioc_pending <- "Bioconductor" %in% fetch
  tables <- list(
    advisories = advisories, advisory_ranges = ranges,
    advisory_affected_versions = ex$rows, advisory_upstream = upstream,
    advisory_history = history,
    advisory_meta = meta_df(iso(now), listed, if (nrow(adv)) max(adv$modified, na.rm = TRUE) else NA))
  export_db(file.path(out_dir, DB_FILENAME), tables)
  file.copy(license_src, file.path(out_dir, LICENSE_ASSET), overwrite = TRUE)
  manifest <- list(
    generated_at = iso(now), cold_start = identical(prev$status, "cold_start"),
    ecosystems_listed = I(listed), ecosystems_fetched = I(fetch),
    tables = lapply(tables, nrow),
    history_earliest = if (nrow(history)) min(history$first_seen) else NA,
    counts = list(advisories_parsed = parsed_n, versions_read = nrow(versions),
                  affected_in_tarballs = affected_in_tarballs,
                  unparsed_versions = ex$unparsed, listed_not_in_tarballs = ex$listed_missing,
                  range_not_in_osv_list = ex$range_not_listed, upstream_lookups = length(ids),
                  upstream_failed = length(failed), advisories_not_in_osv = sum(advisories$in_osv == 0L)),
    bioconductor_expansion_pending = bioc_pending,
    tools = list(script = SCRIPT_VERSION, r = R.version.string,
                 rsqlite = as.character(utils::packageVersion("RSQLite"))))
  write_manifest(file.path(out_dir, "manifest.json"), manifest)
  invisible(manifest)
}

if (sys.nframe() == 0L) {
  args <- commandArgs(trailingOnly = TRUE)
  out_dir <- if (length(args)) args[[1]] else "out"
  # Tests point this at a file defining test_io(), to run the real entrypoint offline.
  io_file <- Sys.getenv("OSV_ADVISORIES_IO")
  io <- if (nzchar(io_file)) { source(io_file); test_io() } else default_io()
  m <- run_update(io, out_dir)
  cat(sprintf("advisories %d, affected versions %d, upstream rows %d, history %d\n",
              m$tables$advisories, m$tables$advisory_affected_versions,
              m$tables$advisory_upstream, m$tables$advisory_history))
}
