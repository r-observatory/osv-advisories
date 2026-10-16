pv <- function(x) package_version(x)

test_that("interval bounds follow OSV: introduced inclusive, fixed exclusive, last_affected inclusive", {
  expect_true(version_in_interval(pv("1.0"), "1.0", "1.2", NA))
  expect_false(version_in_interval(pv("1.2"), "1.0", "1.2", NA))
  expect_false(version_in_interval(pv("0.9"), "1.0", "1.2", NA))
  expect_true(version_in_interval(pv("2.3"), "2.0", NA, "2.3"))
  expect_false(version_in_interval(pv("2.3.1"), "2.0", NA, "2.3"))
  expect_true(version_in_interval(pv("0.0.1"), "0", "1.0", NA))
  expect_true(version_in_interval(pv("9.9"), "1.0", NA, NA))
})

test_that("R version rules apply: 1.2.2 sits before 1.2.2-2", {
  expect_true(version_in_interval(pv("1.2.2"), "0.7.1", "1.2.2-2", NA))
  expect_false(version_in_interval(pv("1.2.2.2"), "0.7.1", "1.2.2-2", NA))
})

test_that("an unparsable bound gives NA", {
  expect_true(is.na(version_in_interval(pv("1.0"), "not a version", "2.0", NA)))
})

test_that("jsonlite 0.9.12 to 1.8.7 are affected and 1.8.8 is not", {
  items <- fixture_items()
  rg <- osv_ranges_df(items, "CRAN")
  vers <- data.frame(package = "jsonlite", version = c("0.9.11", "0.9.12", "1.7.1", "1.8.7", "1.8.8", "2.0.0"),
                     stringsAsFactors = FALSE)
  ex <- expand_affected(rg, osv_listed_df(items, "CRAN")[0, ], vers)
  got <- ex$rows$version[ex$rows$advisory_id == "RSEC-2023-3"]
  expect_equal(got, c("0.9.12", "1.7.1", "1.8.7"))
  expect_true(all(ex$rows$basis == "range"))
})

test_that("the real export against real versions: only widgetframe's current release is hit", {
  items <- fixture_items()
  ex <- expand_affected(osv_ranges_df(items, "CRAN"), osv_listed_df(items, "CRAN"), fixture_versions())
  expect_equal(ex$unparsed, 0L)
  # OSV spells commonmark 1.8.0 and 1.9.0 as "1.8" and "1.9", and lists a jsonlite 1.8.6 CRAN never had.
  expect_equal(ex$listed_missing, 3L)
  phantom <- ex$rows[ex$rows$in_tarballs == 0L, ]
  expect_setequal(paste(phantom$package, phantom$version), c("jsonlite 1.8.6", "commonmark 1.8", "commonmark 1.9"))
  expect_true(all(phantom$basis == "listed"))
  expect_true("0.3.1" %in% ex$rows$version[ex$rows$package == "widgetframe"])
  expect_false("4.12.1" %in% ex$rows$version[ex$rows$package == "plotly"])
})

test_that("a version released after OSV's import is caught by the range alone", {
  items <- list(osv_record("RSEC-X", "pkgA", list(list(introduced = "0.1")), versions = list("0.1", "0.2")))
  vers <- data.frame(package = "pkgA", version = c("0.1", "0.2", "0.3"), stringsAsFactors = FALSE)
  ex <- expand_affected(osv_ranges_df(items, "CRAN"), osv_listed_df(items, "CRAN"), vers)
  expect_equal(ex$rows$basis, c("both", "both", "range"))
  expect_equal(ex$range_not_listed, 1L)
})

test_that("withdrawn advisories and GIT ranges produce no rows", {
  items <- list(osv_record("RSEC-W", "pkgA", list(list(introduced = "0")), withdrawn = "2026-02-01T00:00:00Z"),
                osv_record("RSEC-G", "pkgA", list(list(introduced = "abc123")), range_type = "GIT"))
  vers <- data.frame(package = "pkgA", version = c("0.1", "0.2"), stringsAsFactors = FALSE)
  ex <- expand_affected(osv_ranges_df(items, "CRAN"), osv_listed_df(items, "CRAN"), vers, "RSEC-W")
  expect_equal(nrow(ex$rows), 0L)
})

test_that("a range with an unparsable bound is counted, never read as unaffected", {
  items <- list(osv_record("RSEC-U", "pkgA", list(list(introduced = "0.1"), list(fixed = "v2-beta"))))
  vers <- data.frame(package = "pkgA", version = c("0.1", "0.2"), stringsAsFactors = FALSE)
  ex <- expand_affected(osv_ranges_df(items, "CRAN"), osv_listed_df(items, "CRAN"), vers)
  expect_equal(nrow(ex$rows), 0L)
  expect_equal(ex$unparsed, 1L)
})
