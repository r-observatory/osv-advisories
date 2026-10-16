fake_runner <- function(stdout_lines, status = 0L) {
  function(cmd, args, stdout = "", stderr = "") {
    if (isTRUE(stdout)) stdout_lines else status
  }
}

test_that("release status comes from the first line gh api -i prints", {
  expect_equal(gh_release_status("o/r", "current", fake_runner(c("HTTP/2.0 200 OK", "x"))), 200L)
  expect_equal(gh_release_status("o/r", "current", fake_runner("HTTP/2.0 404 Not Found")), 404L)
  expect_true(is.na(gh_release_status("o/r", "current", fake_runner(character(0)))))
  expect_true(is.na(gh_release_status("o/r", "current", fake_runner("error connecting"))))
})

test_that("a failed or empty asset download throws", {
  dir <- withr::local_tempdir()
  expect_error(gh_download_asset("o/r", "current", "x.db", dir, fake_runner(NULL, 1L)), "could not download")
  file.create(file.path(dir, "x.db"))
  expect_error(gh_download_asset("o/r", "current", "x.db", dir, fake_runner(NULL, 0L)), "could not download")
  writeLines("data", file.path(dir, "x.db"))
  expect_equal(gh_download_asset("o/r", "current", "x.db", dir, fake_runner(NULL, 0L)), file.path(dir, "x.db"))
})
