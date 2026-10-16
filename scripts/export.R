# scripts/export.R: write osv-advisories.db and manifest.json.

TABLE_DDL <- list(
  advisories = "CREATE TABLE advisories (
    id TEXT PRIMARY KEY, ecosystem TEXT NOT NULL, summary TEXT, details TEXT,
    published TEXT, modified TEXT, withdrawn TEXT, upstream TEXT, aliases TEXT,
    related TEXT, credits TEXT, severity TEXT, refs TEXT, schema_version TEXT,
    in_osv INTEGER NOT NULL, first_seen TEXT, raw_json TEXT)",
  advisory_ranges = "CREATE TABLE advisory_ranges (
    advisory_id TEXT NOT NULL, ecosystem TEXT NOT NULL, package TEXT NOT NULL,
    purl TEXT, source_url TEXT, range_seq INTEGER NOT NULL, range_type TEXT,
    introduced TEXT, fixed TEXT, last_affected TEXT, limit_ver TEXT)",
  advisory_affected_versions = "CREATE TABLE advisory_affected_versions (
    advisory_id TEXT NOT NULL, ecosystem TEXT NOT NULL, package TEXT NOT NULL,
    version TEXT NOT NULL, basis TEXT NOT NULL, in_tarballs INTEGER NOT NULL,
    PRIMARY KEY (advisory_id, package, version))",
  advisory_upstream = "CREATE TABLE advisory_upstream (
    advisory_id TEXT NOT NULL, upstream_id TEXT NOT NULL, cvss_type TEXT,
    cvss_vector TEXT, base_score REAL, rating TEXT, lookup_status TEXT NOT NULL,
    fetched_at TEXT)",
  advisory_history = "CREATE TABLE advisory_history (
    advisory_id TEXT NOT NULL, modified TEXT NOT NULL, first_seen TEXT NOT NULL,
    raw_json TEXT, PRIMARY KEY (advisory_id, modified))",
  advisory_meta = "CREATE TABLE advisory_meta (key TEXT PRIMARY KEY, value TEXT)"
)

TABLE_INDEXES <- c(
  "CREATE INDEX idx_aav_package ON advisory_affected_versions (package, version)",
  "CREATE INDEX idx_ar_package ON advisory_ranges (package)"
)

#' Write every table into a fresh database at path. tables is a named list of
#' data frames whose names match TABLE_DDL.
export_db <- function(path, tables) {
  if (file.exists(path)) unlink(path)
  con <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  for (nm in names(TABLE_DDL)) {
    DBI::dbExecute(con, TABLE_DDL[[nm]])
    df <- tables[[nm]]
    if (!is.null(df) && nrow(df)) DBI::dbWriteTable(con, nm, df, append = TRUE)
  }
  for (ix in TABLE_INDEXES) DBI::dbExecute(con, ix)
  invisible(path)
}

#' The previous release's tables, read back from its database file.
read_prev_tables <- function(path) {
  con <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  get <- function(t) if (DBI::dbExistsTable(con, t)) DBI::dbReadTable(con, t) else NULL
  list(advisories = get("advisories"), advisory_history = get("advisory_history"),
       advisory_upstream = get("advisory_upstream"))
}

meta_df <- function(fetched_at, listed, osv_modified_max) {
  data.frame(
    key = c("fetched_at", "ecosystems_listed", "osv_modified_max", "analyzer"),
    value = c(fetched_at, as.character(jsonlite::toJSON(listed)),
              osv_modified_max %||% NA_character_,
              sprintf("osv-advisories %s, %s", SCRIPT_VERSION, R.version.string)),
    stringsAsFactors = FALSE)
}

write_manifest <- function(path, obj) {
  jsonlite::write_json(obj, path, auto_unbox = TRUE, pretty = TRUE, null = "null", na = "null")
  invisible(path)
}
