test_that("a cold start writes all six tables, the raw zip, the licence and the manifest", {
  out <- withr::local_tempdir()
  m <- run_update(fake_io(), out, license_fixture())
  expect_setequal(list.files(out), c(DB_FILENAME, "manifest.json", "osv-CRAN-all.zip", LICENSE_ASSET))
  expect_true(m$cold_start)
  expect_equal(m$tables$advisories, 14L)
  expect_equal(m$tables$advisory_history, 14L)
  expect_equal(m$tables$advisory_upstream, 30L)
  expect_equal(m$counts$listed_not_in_tarballs, 3L)
  expect_equal(m$history_earliest, "2026-10-15")
  man <- jsonlite::read_json(file.path(out, "manifest.json"))
  expect_equal(man$ecosystems_fetched, list("CRAN"))
  meta <- read_table(out, "advisory_meta")
  expect_equal(meta$value[meta$key == "fetched_at"], "2026-10-15T06:00:00Z")
  expect_equal(jsonlite::fromJSON(meta$value[meta$key == "ecosystems_listed"]), c("CRAN", "Go"))
  adv <- read_table(out, "advisories")
  expect_true(all(adv$in_osv == 1L) && all(adv$first_seen == "2026-10-15"))
})

test_that("the next day with nothing changed adds no history and keeps first_seen", {
  day1 <- withr::local_tempdir(); day2 <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  m2 <- run_update(fake_io(prev = prev_from(day1), now = as.POSIXct("2026-10-16 06:00:00", tz = "UTC")),
                   day2, license_fixture())
  expect_false(m2$cold_start)
  expect_equal(m2$tables$advisory_history, 14L)
  expect_equal(m2$history_earliest, "2026-10-15")
  expect_true(all(read_table(day2, "advisories")$first_seen == "2026-10-15"))
})

test_that("a changed advisory adds a dated history row", {
  skip_if(Sys.which("zip") == "", "zip is not installed")
  day1 <- withr::local_tempdir(); day2 <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  src <- withr::local_tempdir(); utils::unzip(fixture_zip(), exdir = src)
  f <- file.path(src, "RSEC-2023-3.json")
  rec <- jsonlite::read_json(f); rec$modified <- "2026-10-16T01:00:00Z"
  jsonlite::write_json(rec, f, auto_unbox = TRUE)
  zip2 <- file.path(withr::local_tempdir(), "changed.zip")
  utils::zip(zip2, list.files(src, full.names = TRUE), flags = "-jq")
  m2 <- run_update(fake_io(prev = prev_from(day1), zips = list(CRAN = zip2),
                           now = as.POSIXct("2026-10-16 06:00:00", tz = "UTC")), day2, license_fixture())
  expect_equal(m2$tables$advisory_history, 15L)
  h <- read_table(day2, "advisory_history")
  expect_equal(h$first_seen[h$advisory_id == "RSEC-2023-3"], c("2026-10-15", "2026-10-16"))
})

test_that("an advisory dropped by OSV is kept, and the count never falls", {
  skip_if(Sys.which("zip") == "", "zip is not installed")
  day1 <- withr::local_tempdir(); day2 <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  src <- withr::local_tempdir(); utils::unzip(fixture_zip(), exdir = src)
  unlink(file.path(src, "RSEC-2026-1.json"))
  zip2 <- file.path(withr::local_tempdir(), "fewer.zip")
  utils::zip(zip2, list.files(src, full.names = TRUE), flags = "-jq")
  m2 <- run_update(fake_io(prev = prev_from(day1), zips = list(CRAN = zip2)), day2, license_fixture())
  expect_equal(m2$tables$advisories, 14L)
  expect_equal(m2$counts$advisories_not_in_osv, 1L)
  adv <- read_table(day2, "advisories")
  expect_equal(adv$in_osv[adv$id == "RSEC-2026-1"], 0L)
})

test_that("Bioconductor is fetched only when OSV lists it, and then flagged", {
  seen <- new.env()
  run_update(fake_io(seen = seen), withr::local_tempdir(), license_fixture())
  expect_equal(seen$zips, "CRAN")
  bioc_zip <- file.path(withr::local_tempdir(), "empty.zip")
  skip_if(Sys.which("zip") == "", "zip is not installed")
  tmp <- withr::local_tempdir(); writeLines("{}", file.path(tmp, "README.txt"))
  utils::zip(bioc_zip, file.path(tmp, "README.txt"), flags = "-jq")
  seen2 <- new.env()
  m <- run_update(fake_io(ecosystems = "Bioconductor\nCRAN\n", zips = list(CRAN = fixture_zip(), Bioconductor = bioc_zip),
                          seen = seen2), withr::local_tempdir(), license_fixture())
  expect_equal(seen2$zips, c("CRAN", "Bioconductor"))
  expect_true(m$bioconductor_expansion_pending)
})

test_that("the run stops when CRAN is not listed or the previous release cannot be read", {
  expect_error(run_update(fake_io(ecosystems = "Go\n"), withr::local_tempdir(), license_fixture()),
               "does not list CRAN")
  broken <- function() stop("release current: status 502")
  expect_error(run_update(fake_io(prev = broken), withr::local_tempdir(), license_fixture()), "status 502")
})

test_that("the run refuses to publish fewer advisories than the last release declared", {
  day1 <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  prev <- prev_from(day1); prev$manifest$tables$advisories <- 20L
  out <- withr::local_tempdir()
  expect_error(run_update(fake_io(prev = prev), out, license_fixture()), "advisories fell from 20 to 14")
  expect_false(file.exists(file.path(out, DB_FILENAME)))
})

test_that("a failed upstream lookup still publishes and is counted", {
  out <- withr::local_tempdir()
  m <- run_update(fake_io(vuln = function(id) list(status = "failed", record = NULL)), out, license_fixture())
  expect_equal(m$counts$upstream_failed, 30L)
  up <- read_table(out, "advisory_upstream")
  expect_true(all(up$lookup_status == "failed"))
})

test_that("the same advisory id in two ecosystems stops the run", {
  expect_error(run_update(fake_io(ecosystems = "Bioconductor\nCRAN\n",
                                  zips = list(CRAN = fixture_zip(), Bioconductor = fixture_zip())),
                          withr::local_tempdir(), license_fixture()),
               "duplicate advisory ids")
})

# A copy of the fixture zip made from a directory edited by edit(dir).
zip_variant <- function(edit) {
  src <- withr::local_tempdir(.local_envir = parent.frame())
  utils::unzip(fixture_zip(), exdir = src)
  edit(src)
  zip <- file.path(withr::local_tempdir(.local_envir = parent.frame()), "variant.zip")
  utils::zip(zip, list.files(src, full.names = TRUE), flags = "-jq")
  zip
}

test_that("with a previous release, a corrupt zip stops the run", {
  skip_if(Sys.which("zip") == "", "zip is not installed")
  day1 <- withr::local_tempdir(); out <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  bad <- file.path(withr::local_tempdir(), "bad.zip")
  writeLines("this is not a zip file", bad)
  expect_error(run_update(fake_io(prev = prev_from(day1), zips = list(CRAN = bad)), out, license_fixture()))
  expect_false(file.exists(file.path(out, DB_FILENAME)))
  # One damaged entry only makes unzip warn; the run must still stop.
  raw <- readBin(fixture_zip(), "raw", file.size(fixture_zip()))
  raw[300:340] <- as.raw(0xFF)
  trunc <- file.path(withr::local_tempdir(), "damaged.zip")
  writeBin(raw, trunc)
  expect_error(run_update(fake_io(prev = prev_from(day1), zips = list(CRAN = trunc)), out, license_fixture()))
  expect_false(file.exists(file.path(out, DB_FILENAME)))
})

test_that("unzip_strict fails on a truncated zip and on a file count that does not match", {
  dir <- withr::local_tempdir()
  expect_length(unzip_strict(fixture_zip(), dir), 14L)
  raw <- readBin(fixture_zip(), "raw", file.size(fixture_zip()))
  cut <- file.path(withr::local_tempdir(), "cut.zip")
  writeBin(raw[seq_len(length(raw) %/% 2)], cut)
  expect_error(suppressWarnings(unzip_strict(cut, withr::local_tempdir())))
  stray <- withr::local_tempdir(); writeLines("{}", file.path(stray, "stray.json"))
  expect_error(unzip_strict(fixture_zip(), stray), "14 .json entries listed, 15 extracted")
})

test_that("a zip missing more advisories than the tolerance stops the run and writes no database", {
  skip_if(Sys.which("zip") == "", "zip is not installed")
  day1 <- withr::local_tempdir(); out <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  few <- zip_variant(function(d) unlink(list.files(d, full.names = TRUE)[-(1:2)]))
  expect_error(run_update(fake_io(prev = prev_from(day1), zips = list(CRAN = few)), out, license_fixture()),
               "advisories parsed fell from 14 to 2")
  expect_false(file.exists(file.path(out, DB_FILENAME)))
})

test_that("an empty export stops the run, cold start or not", {
  skip_if(Sys.which("zip") == "", "zip is not installed")
  none <- zip_variant(function(d) { writeLines("x", file.path(d, "README.txt")); unlink(list.files(d, "json$", full.names = TRUE)) })
  expect_error(run_update(fake_io(zips = list(CRAN = none)), withr::local_tempdir(), license_fixture()),
               "no advisories parsed")
})

test_that("the previous parsed count falls back to the table count minus the missing ones", {
  day1 <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  prev <- prev_from(day1); prev$manifest$counts$advisories_parsed <- NULL
  prev$manifest$tables$advisories <- 30L
  expect_error(run_update(fake_io(prev = prev), withr::local_tempdir(), license_fixture()),
               "advisories parsed fell from 30 to 14")
})

test_that("the manifest records the parsed, version and tarball counts", {
  m <- run_update(fake_io(), withr::local_tempdir(), license_fixture())
  expect_equal(m$counts$advisories_parsed, 14L)
  expect_equal(m$counts$versions_read, nrow(fixture_versions()))
  expect_gt(m$counts$affected_in_tarballs, 0L)
})

test_that("an empty cran-archive version list stops the run", {
  expect_error(run_update(fake_io(versions = fixture_versions()[0, ]), withr::local_tempdir(), license_fixture()),
               "no CRAN versions read")
})

test_that("a version list far below the last run, or no tarball matches after some, stops the run", {
  day1 <- withr::local_tempdir()
  run_update(fake_io(), day1, license_fixture())
  prev <- prev_from(day1); prev$manifest$counts$versions_read <- 100000L
  expect_error(run_update(fake_io(prev = prev), withr::local_tempdir(), license_fixture()),
               "CRAN versions read fell from 100000")
  prev <- prev_from(day1)
  other <- data.frame(package = "zzz", version = "1.0", stringsAsFactors = FALSE)
  prev$manifest$counts$versions_read <- 1L
  expect_error(run_update(fake_io(prev = prev, versions = other), withr::local_tempdir(), license_fixture()),
               "no affected version matched a tarball")
})

test_that("a throwing osv_vuln, or a record with a odd severity, still publishes", {
  out <- withr::local_tempdir()
  m <- run_update(fake_io(vuln = function(id) stop("boom")), out, license_fixture())
  expect_equal(m$counts$upstream_failed, 30L)
  expect_true(all(read_table(out, "advisory_upstream")$lookup_status == "failed"))
  out2 <- withr::local_tempdir()
  m2 <- run_update(fake_io(vuln = function(id) list(status = "ok", record = list(severity = "high"))),
                   out2, license_fixture())
  expect_equal(m2$counts$upstream_failed, 0L)
  up <- read_table(out2, "advisory_upstream")
  expect_true(all(is.na(up$cvss_vector)))
})

test_that("an unexpected previous-release status stops the run", {
  expect_error(run_update(fake_io(prev = list(status = "weird")), withr::local_tempdir(), license_fixture()),
               "weird")
})

test_that("every stored upstream value is a JSON array", {
  out <- withr::local_tempdir()
  run_update(fake_io(), out, license_fixture())
  adv <- read_table(out, "advisories")
  expect_true(all(substr(adv$upstream[!is.na(adv$upstream)], 1, 1) == "["))
  expect_match(adv$upstream[adv$id == "RSEC-2023-6"], "^\\[")
})
