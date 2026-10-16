# The workflow runs `Rscript scripts/update.R out` from the repository root. Run
# exactly that, in a copy of the repository, with the network swapped for fixtures.
test_that("the entrypoint runs with the workflow's arguments and working directory", {
  root <- normalizePath(testthat::test_path("..", ".."))
  work <- withr::local_tempdir()
  file.copy(file.path(root, "scripts"), work, recursive = TRUE)
  file.copy(file.path(root, LICENSE_ASSET), work)
  io_file <- file.path(work, "test-io.R")
  writeLines(c(
    sprintf('ZIP <- "%s"', normalizePath(fixture_zip())),
    sprintf('VERS <- "%s"', normalizePath(testthat::test_path("fixtures", "cran-versions.csv"))),
    'test_io <- function() list(',
    '  ecosystems = function() "CRAN\\n",',
    '  osv_zip = function(ecosystem, dest) { file.copy(ZIP, dest, overwrite = TRUE); dest },',
    '  prev_state = function() list(status = "cold_start"),',
    '  archive_versions = function() utils::read.csv(VERS, colClasses = "character"),',
    '  osv_vuln = function(id) list(status = "not_in_osv", record = NULL),',
    '  now = function() Sys.time())'), io_file)
  out <- withr::with_dir(work, system2(file.path(R.home("bin"), "Rscript"), c("scripts/update.R", "out"),
                                       stdout = TRUE, stderr = TRUE, env = paste0("OSV_ADVISORIES_IO=", io_file)))
  expect_null(attr(out, "status"))
  expect_true(any(grepl("^advisories 14", out)))
  expect_setequal(list.files(file.path(work, "out")),
                  c(DB_FILENAME, "manifest.json", "osv-CRAN-all.zip", LICENSE_ASSET))
})
