adv_df <- function(ids, modified = rep("2026-01-01T00:00:00Z", length(ids))) {
  df <- empty_advisories()[seq_along(ids), ]
  df$id <- ids; df$ecosystem <- "CRAN"; df$modified <- modified; df$raw_json <- paste0("{", ids, "}")
  rownames(df) <- NULL
  df
}

test_that("history adds a row only for a new modified value", {
  h1 <- merge_history(NULL, adv_df(c("A", "B")), "2026-10-15")
  expect_equal(nrow(h1), 2L)
  h2 <- merge_history(h1, adv_df(c("A", "B")), "2026-10-16")
  expect_equal(nrow(h2), 2L)
  h3 <- merge_history(h2, adv_df(c("A", "B"), c("2026-03-01T00:00:00Z", "2026-01-01T00:00:00Z")), "2026-10-17")
  expect_equal(nrow(h3), 3L)
  expect_equal(h3$first_seen[h3$advisory_id == "A"], c("2026-10-15", "2026-10-17"))
})

test_that("an advisory gone from OSV is carried with in_osv 0 and keeps its first_seen", {
  hist <- merge_history(NULL, adv_df(c("A", "B")), "2026-10-15")
  prev <- carry_forward(NULL, adv_df(c("A", "B")), hist)
  expect_equal(prev$in_osv, c(1L, 1L))
  expect_equal(prev$first_seen, c("2026-10-15", "2026-10-15"))
  hist2 <- merge_history(hist, adv_df("A"), "2026-10-16")
  now <- carry_forward(prev, adv_df("A"), hist2)
  expect_equal(now$id, c("A", "B"))
  expect_equal(now$in_osv, c(1L, 0L))
  expect_equal(now$first_seen[now$id == "B"], "2026-10-15")
})

test_that("a failed upstream lookup keeps the previous rows, or shows the failure", {
  fresh <- data.frame(advisory_id = c("A", "A"), upstream_id = c("CVE-1", "CVE-2"),
                      cvss_type = NA_character_, cvss_vector = NA_character_, base_score = NA_real_,
                      rating = NA_character_, lookup_status = "failed", fetched_at = "t2",
                      stringsAsFactors = FALSE)
  prev <- fresh[1, ]; prev$cvss_type <- "CVSS_V3"; prev$cvss_vector <- "CVSS:3.1/x"
  prev$base_score <- 6.5; prev$rating <- "Medium"; prev$lookup_status <- "ok"; prev$fetched_at <- "t1"
  out <- carry_upstream(prev, fresh, c("CVE-1", "CVE-2"))
  expect_equal(out$lookup_status, c("failed_kept_previous", "failed"))
  expect_equal(out$base_score[1], 6.5)
  ok <- fresh; ok$lookup_status <- "ok"
  expect_equal(carry_upstream(prev, ok, character(0)), ok)
})

test_that("guards: cold start passes, shrinking or empty does not", {
  hist <- merge_history(NULL, adv_df(c("A", "B")), "2026-10-15")
  adv <- carry_forward(NULL, adv_df(c("A", "B")), hist)
  expect_length(publish_guard(NULL, adv, hist), 0L)
  expect_match(publish_guard(NULL, adv[0, ], hist[0, ]), "no advisories")
  prev_m <- list(tables = list(advisories = 3L, advisory_history = 2L), history_earliest = "2026-10-15")
  expect_match(publish_guard(prev_m, adv, hist), "advisories fell from 3 to 2")
  prev_m2 <- list(tables = list(advisories = 2L, advisory_history = 5L), history_earliest = "2026-10-15")
  expect_match(publish_guard(prev_m2, adv, hist), "advisory_history fell")
  prev_m3 <- list(tables = list(advisories = 2L, advisory_history = 2L), history_earliest = "2026-10-01")
  expect_match(publish_guard(prev_m3, adv, hist), "lost its earliest row")
  prev_ok <- list(tables = list(advisories = 2L, advisory_history = 2L), history_earliest = "2026-10-15")
  expect_length(publish_guard(prev_ok, adv, hist), 0L)
})

test_that("merge_history with no advisories returns the previous history", {
  h1 <- merge_history(NULL, adv_df(c("A", "B")), "2026-10-15")
  expect_equal(merge_history(h1, empty_advisories(), "2026-10-16"), h1)
  expect_equal(nrow(merge_history(NULL, empty_advisories(), "2026-10-16")), 0L)
})

up_row <- function(adv, uid, status, vec = NA_character_) {
  data.frame(advisory_id = adv, upstream_id = uid, cvss_type = if (is.na(vec)) NA_character_ else "CVSS_V3",
             cvss_vector = vec, base_score = NA_real_, rating = NA_character_,
             lookup_status = status, fetched_at = "t", stringsAsFactors = FALSE)
}

test_that("a repeated failure stays failed, and kept rows match on advisory and upstream id", {
  fresh <- up_row("A", "CVE-1", "failed")
  prev <- up_row("A", "CVE-1", "failed")
  expect_equal(carry_upstream(prev, fresh, "CVE-1")$lookup_status, "failed")
  prev2 <- up_row("A", "CVE-1", "failed_kept_previous", "CVSS:3.1/x")
  out2 <- carry_upstream(prev2, fresh, "CVE-1")
  expect_equal(out2$lookup_status, "failed_kept_previous")
  expect_equal(out2$cvss_vector, "CVSS:3.1/x")
  fresh2 <- rbind(up_row("A", "CVE-1", "failed"), up_row("B", "CVE-1", "failed"))
  prev3 <- rbind(up_row("A", "CVE-1", "ok", "CVSS:3.1/a"), up_row("B", "CVE-1", "failed"))
  out3 <- carry_upstream(prev3, fresh2, "CVE-1")
  expect_equal(out3$advisory_id, c("A", "B"))
  expect_equal(out3$lookup_status, c("failed_kept_previous", "failed"))
  expect_equal(out3$cvss_vector, c("CVSS:3.1/a", NA))
})
