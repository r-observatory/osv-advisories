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
