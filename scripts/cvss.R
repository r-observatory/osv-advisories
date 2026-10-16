# scripts/cvss.R: CVSS 3.0 and 3.1 base score from a vector string.
#
# The formula is the one published in the FIRST specification (section 7.1 of
# CVSS v3.1). Other vector versions get no score: the caller stores the vector
# and leaves the score NA.

CVSS3_WEIGHTS <- list(
  AV = c(N = 0.85, A = 0.62, L = 0.55, P = 0.2),
  AC = c(L = 0.77, H = 0.44),
  UI = c(N = 0.85, R = 0.62),
  CIA = c(H = 0.56, L = 0.22, N = 0)
)

#' Round up to one decimal the way CVSS 3.1 defines it, immune to float noise.
cvss3_roundup <- function(x) {
  i <- round(x * 100000)
  if (i %% 10000 == 0) i / 100000 else (floor(i / 10000) + 1) / 10
}

#' Parse "CVSS:3.1/AV:N/..." into a named character vector, or NULL when the
#' string is not a complete CVSS 3.x base vector.
parse_cvss3 <- function(vector) {
  if (!is.character(vector) || length(vector) != 1L || is.na(vector)) return(NULL)
  parts <- strsplit(vector, "/", fixed = TRUE)[[1]]
  if (!length(parts) || !parts[1] %in% c("CVSS:3.0", "CVSS:3.1")) return(NULL)
  kv <- strsplit(parts[-1], ":", fixed = TRUE)
  if (any(lengths(kv) != 2L)) return(NULL)
  m <- setNames(vapply(kv, `[`, "", 2L), vapply(kv, `[`, "", 1L))
  need <- c("AV", "AC", "PR", "UI", "S", "C", "I", "A")
  if (!all(need %in% names(m))) return(NULL)
  m[need]
}

#' Base score (0.0 to 10.0) of a CVSS 3.0 or 3.1 vector, NA for anything else.
cvss3_base_score <- function(vector) {
  m <- parse_cvss3(vector)
  if (is.null(m)) return(NA_real_)
  w <- CVSS3_WEIGHTS
  scope_changed <- m[["S"]] == "C"
  pr <- if (scope_changed) c(N = 0.85, L = 0.68, H = 0.5) else c(N = 0.85, L = 0.62, H = 0.27)
  vals <- c(w$AV[m[["AV"]]], w$AC[m[["AC"]]], pr[m[["PR"]]], w$UI[m[["UI"]]],
            w$CIA[m[["C"]]], w$CIA[m[["I"]]], w$CIA[m[["A"]]])
  if (anyNA(vals) || !m[["S"]] %in% c("U", "C")) return(NA_real_)
  iss <- 1 - (1 - vals[[5]]) * (1 - vals[[6]]) * (1 - vals[[7]])
  impact <- if (scope_changed) 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)^15 else 6.42 * iss
  exploit <- 8.22 * vals[[1]] * vals[[2]] * vals[[3]] * vals[[4]]
  if (impact <= 0) return(0)
  if (scope_changed) cvss3_roundup(min(1.08 * (impact + exploit), 10))
  else cvss3_roundup(min(impact + exploit, 10))
}

#' Qualitative rating for a base score, NA for NA.
cvss_rating <- function(score) {
  if (is.na(score)) return(NA_character_)
  if (score == 0) "None" else if (score < 4) "Low" else if (score < 7) "Medium"
  else if (score < 9) "High" else "Critical"
}

#' One row per advisory, upstream id and severity entry.
#'
#' lookups is a named list, upstream id -> list(status, record), where status is
#' "ok", "not_in_osv" or "failed" and record is the parsed OSV record when ok.
#' An id with no severity entry, or one that was not found or failed, still gets
#' one row so the advisory shows the id.
upstream_rows <- function(adv, lookups, fetched_at) {
  rows <- list()
  for (i in seq_len(nrow(adv))) {
    ids <- if (is.na(adv$upstream[i])) character(0) else as.character(jsonlite::fromJSON(adv$upstream[i]))
    for (uid in ids) {
      lk <- lookups[[uid]] %||% list(status = "failed", record = NULL)
      sev <- if (identical(lk$status, "ok")) lk$record$severity %||% list() else list()
      sev <- Filter(function(x) is.list(x) && !is.null(x$type) && !is.null(x$score), as.list(sev))
      if (!length(sev)) sev <- list(list(type = NA_character_, score = NA_character_))
      for (s in sev) {
        score <- if (identical(s$type, "CVSS_V3")) cvss3_base_score(s$score) else NA_real_
        rows[[length(rows) + 1L]] <- data.frame(
          advisory_id = adv$id[i], upstream_id = uid,
          cvss_type = s$type %||% NA_character_, cvss_vector = s$score %||% NA_character_,
          base_score = score, rating = cvss_rating(score),
          lookup_status = lk$status, fetched_at = fetched_at, stringsAsFactors = FALSE)
      }
    }
  }
  if (!length(rows)) {
    return(data.frame(advisory_id = character(0), upstream_id = character(0), cvss_type = character(0),
                      cvss_vector = character(0), base_score = numeric(0), rating = character(0),
                      lookup_status = character(0), fetched_at = character(0), stringsAsFactors = FALSE))
  }
  do.call(rbind, rows)
}
