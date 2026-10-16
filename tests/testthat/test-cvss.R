test_that("CVSS 3.x base scores match NVD's published scores", {
  cases <- c(
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" = 6.5,   # CVE-2020-5238, behind commonmark
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" = 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" = 6.1,
    "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" = 7.8,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" = 9.9,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" = 8.8,   # CVE-2017-12108, behind readxl
    "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L" = 3.5,   # CVE-2023-22483, behind commonmark
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N" = 0
  )
  for (v in names(cases)) expect_equal(cvss3_base_score(v), cases[[v]], info = v)
})

test_that("ratings follow the CVSS bands", {
  expect_equal(vapply(c(0, 3.5, 6.5, 8.8, 9.8), cvss_rating, ""),
               c("None", "Low", "Medium", "High", "Critical"))
  expect_true(is.na(cvss_rating(NA_real_)))
})

test_that("a CVSS 4.0 vector or a broken string gets no score", {
  expect_true(is.na(cvss3_base_score("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N")))
  expect_true(is.na(cvss3_base_score("CVSS:3.1/AV:N/AC:L")))
  expect_true(is.na(cvss3_base_score("CVSS:3.1/AV:X/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")))
  expect_true(is.na(cvss3_base_score(NA_character_)))
})

test_that("upstream rows keep every id, scored or not", {
  adv <- data.frame(id = c("A", "B"), upstream = c('["CVE-1","CVE-2"]', NA), stringsAsFactors = FALSE)
  lookups <- list(
    "CVE-1" = list(status = "ok", record = list(severity = list(list(type = "CVSS_V3",
      score = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")))),
    "CVE-2" = list(status = "not_in_osv", record = NULL))
  rows <- upstream_rows(adv, lookups, "2026-10-15T06:00:00Z")
  expect_equal(nrow(rows), 2L)
  expect_equal(rows$base_score[rows$upstream_id == "CVE-1"], 6.5)
  expect_equal(rows$rating[rows$upstream_id == "CVE-1"], "Medium")
  expect_equal(rows$lookup_status[rows$upstream_id == "CVE-2"], "not_in_osv")
  expect_true(is.na(rows$cvss_vector[rows$upstream_id == "CVE-2"]))
  v4 <- list("CVE-1" = list(status = "ok", record = list(severity = list(list(type = "CVSS_V4", score = "CVSS:4.0/AV:N")))))
  r4 <- upstream_rows(adv[1, ], v4, "t")
  expect_equal(r4$cvss_vector[1], "CVSS:4.0/AV:N")
  expect_true(is.na(r4$base_score[1]))
})

test_that("a severity entry that is not an object with type and score counts as absent", {
  adv <- data.frame(id = "A", upstream = '["CVE-1"]', stringsAsFactors = FALSE)
  for (sev in list("high", list("a", "b"), list(list(type = "CVSS_V3")), 5)) {
    lk <- list("CVE-1" = list(status = "ok", record = list(severity = sev)))
    rows <- upstream_rows(adv, lk, "t")
    expect_equal(nrow(rows), 1L)
    expect_true(is.na(rows$cvss_vector) && is.na(rows$base_score))
    expect_equal(rows$lookup_status, "ok")
  }
})
