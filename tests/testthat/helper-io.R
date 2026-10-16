# A fake io for run_update(): fixtures in place of the network and GitHub.
fake_io <- function(prev = list(status = "cold_start"), ecosystems = "CRAN\nGo\n",
                    zips = list(CRAN = fixture_zip()), versions = fixture_versions(),
                    vuln = function(id) list(status = "ok", record = list(severity = list(list(
                      type = "CVSS_V3", score = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")))),
                    now = as.POSIXct("2026-10-15 06:00:00", tz = "UTC"), seen = new.env()) {
  seen$zips <- character(0)
  list(
    ecosystems = function() ecosystems,
    osv_zip = function(ecosystem, dest) {
      seen$zips <- c(seen$zips, ecosystem)
      if (is.null(zips[[ecosystem]])) stop("no fixture for ", ecosystem)
      file.copy(zips[[ecosystem]], dest, overwrite = TRUE)
      dest
    },
    prev_state = function() if (is.function(prev)) prev() else prev,
    archive_versions = function() versions,
    osv_vuln = vuln,
    now = function() now
  )
}

# The previous release, as prev_state() would hand it over, from an earlier out_dir.
prev_from <- function(out_dir) {
  list(status = "ok", db = file.path(out_dir, DB_FILENAME),
       manifest = jsonlite::read_json(file.path(out_dir, "manifest.json")))
}

license_fixture <- function() {
  path <- withr::local_tempfile(fileext = ".txt", .local_envir = parent.frame())
  writeLines("Apache License 2.0 (fixture)", path)
  path
}

read_table <- function(out_dir, table) {
  con <- DBI::dbConnect(RSQLite::SQLite(), file.path(out_dir, DB_FILENAME))
  on.exit(DBI::dbDisconnect(con))
  DBI::dbReadTable(con, table)
}
