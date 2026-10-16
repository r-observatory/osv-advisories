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

test_that("an OSV record response that does not parse is a failed lookup", {
  expect_equal(parse_vuln_response(200L, charToRaw("<html>nope"))$status, "failed")
  expect_equal(parse_vuln_response(200L, charToRaw('{"id":"X"}'))$status, "ok")
  expect_equal(parse_vuln_response(404L, raw(0))$status, "not_in_osv")
  expect_equal(parse_vuln_response(500L, raw(0))$status, "failed")
})

test_that("http_get passes a handle with connect and total timeouts", {
  seen <- new.env()
  fetch <- function(url, handle) { seen$handle <- handle; list(status_code = 200L, content = raw(0)) }
  expect_equal(http_get("https://example.org", fetch = fetch)$status, 200L)
  expect_s3_class(seen$handle, "curl_handle")
  expect_equal(c(HTTP_CONNECT_TIMEOUT_S, HTTP_TIMEOUT_S), c(20, 300))
})
