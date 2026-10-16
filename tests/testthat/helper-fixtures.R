# Shared fixtures: the real OSV CRAN export of 2026-10-15 (14 advisories) and the
# CRAN versions of the ten packages it names, read from CRAN that day.

fixture_zip <- function() testthat::test_path("fixtures", "osv-CRAN-all.zip")

fixture_items <- function() {
  dir <- withr::local_tempdir(.local_envir = parent.frame())
  utils::unzip(fixture_zip(), exdir = dir)
  read_osv_dir(dir)
}

fixture_versions <- function() {
  utils::read.csv(testthat::test_path("fixtures", "cran-versions.csv"),
                  colClasses = "character", stringsAsFactors = FALSE)
}

# A minimal OSV record as parse_json() would return it.
osv_record <- function(id, package, events, versions = NULL, modified = "2026-01-01T00:00:00Z",
                       withdrawn = NULL, upstream = NULL, range_type = "ECOSYSTEM") {
  r <- list(id = id, summary = paste("summary", id), details = "details",
            published = "2025-01-01T00:00:00Z", modified = modified,
            affected = list(list(package = list(name = package, ecosystem = "CRAN",
                                                purl = paste0("pkg:cran/", package)),
                                 ranges = list(list(type = range_type, events = events)),
                                 versions = versions,
                                 database_specific = list(source = paste0("https://example.org/", id)))),
            schema_version = "1.7.3")
  if (!is.null(withdrawn)) r$withdrawn <- withdrawn
  if (!is.null(upstream)) r$upstream <- as.list(upstream)
  list(record = r, raw = as.character(jsonlite::toJSON(r, auto_unbox = TRUE)))
}
