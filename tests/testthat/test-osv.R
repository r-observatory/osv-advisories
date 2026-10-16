test_that("ecosystems.txt is read one name per line and only wanted ones are fetched", {
  listed <- parse_ecosystems("AlmaLinux\nCRAN\n\n  Go  \n")
  expect_equal(listed, c("AlmaLinux", "CRAN", "Go"))
  expect_equal(ecosystems_to_fetch(listed), "CRAN")
  expect_equal(ecosystems_to_fetch(c("Bioconductor", "CRAN")), c("CRAN", "Bioconductor"))
  expect_equal(ecosystems_to_fetch(c("Go")), character(0))
})

test_that("events become intervals, including several in one range and last_affected", {
  iv <- events_to_intervals(list(list(introduced = "1.0"), list(fixed = "1.2"),
                                 list(introduced = "2.0"), list(last_affected = "2.3")))
  expect_length(iv, 2L)
  expect_equal(unname(iv[[1]][c("introduced", "fixed")]), c("1.0", "1.2"))
  expect_true(is.na(iv[[1]][["last_affected"]]))
  expect_equal(unname(iv[[2]][c("introduced", "last_affected")]), c("2.0", "2.3"))
  open <- events_to_intervals(list(list(introduced = "0.1.0")))
  expect_true(is.na(open[[1]][["fixed"]]) && is.na(open[[1]][["last_affected"]]))
  lim <- events_to_intervals(list(list(introduced = "0"), list(limit = "3.0")))
  expect_equal(lim[[1]][["limit_ver"]], "3.0")
})

test_that("the real export parses into 14 advisories over 10 packages", {
  items <- fixture_items()
  adv <- osv_advisories_df(items, "CRAN")
  expect_equal(nrow(adv), 14L)
  expect_true(all(c("RSEC-2023-0", "RSEC-2026-1") %in% adv$id))
  cm <- adv[adv$id == "RSEC-2023-6", ]
  expect_equal(jsonlite::fromJSON(cm$upstream), "CVE-2020-5238")
  expect_match(cm$upstream, "^\\[")
  expect_true(all(substr(adv$upstream[!is.na(adv$upstream)], 1, 1) == "["))
  expect_true(all(is.na(adv$aliases)) && all(is.na(adv$withdrawn)))
  refs <- jsonlite::fromJSON(cm$refs)
  expect_true(all(c("type", "url") %in% names(refs)))
  expect_true(all(nzchar(adv$raw_json)))

  rg <- osv_ranges_df(items, "CRAN")
  expect_equal(length(unique(rg$package)), 10L)
  wf <- rg[rg$advisory_id == "RSEC-2026-0", ]
  expect_equal(wf$package, "widgetframe")
  expect_true(is.na(wf$fixed))
  expect_match(wf$source_url, "r-advisory-database")

  expect_equal(length(upstream_ids(adv)), 30L)
  ls <- osv_listed_df(items, "CRAN")
  expect_true("1.8.6" %in% ls$version[ls$package == "jsonlite"])
})

test_that("an empty export gives zero-row tables with the right columns", {
  expect_equal(nrow(osv_advisories_df(list(), "CRAN")), 0L)
  expect_true("range_seq" %in% names(osv_ranges_df(list(), "CRAN")))
  expect_equal(nrow(osv_listed_df(list(), "CRAN")), 0L)
})

test_that("only .json files are read, so a stray file in the zip is ignored", {
  dir <- withr::local_tempdir()
  utils::unzip(fixture_zip(), exdir = dir, files = "RSEC-2023-3.json")
  writeLines("not an advisory", file.path(dir, "README.txt"))
  items <- read_osv_dir(dir)
  expect_length(items, 1L)
  expect_equal(items[[1]]$record$id, "RSEC-2023-3")
})

test_that("upstream, aliases and related are always JSON arrays", {
  it <- osv_record("X-1", "pkg", list(list(introduced = "0")), upstream = "CVE-1")
  it$record$aliases <- list("GHSA-1"); it$record$related <- list("R-1", "R-2")
  adv <- osv_advisories_df(list(it), "CRAN")
  expect_equal(adv$upstream, '["CVE-1"]')
  expect_equal(adv$aliases, '["GHSA-1"]')
  expect_equal(adv$related, '["R-1","R-2"]')
  none <- osv_advisories_df(list(osv_record("X-2", "pkg", list(list(introduced = "0")))), "CRAN")
  expect_true(is.na(none$upstream) && is.na(none$aliases) && is.na(none$related))
})
