# scripts/state.R: what carries over from the previous release. Pure.

#' advisory_history with a row added for every (id, modified) not seen before,
#' stamped with today. prev may be NULL (cold start).
merge_history <- function(prev, adv, today) {
  prev <- if (is.null(prev)) empty_history() else prev[, names(empty_history()), drop = FALSE]
  cur <- data.frame(advisory_id = adv$id, modified = adv$modified, first_seen = today,
                    raw_json = adv$raw_json, stringsAsFactors = FALSE)
  new <- cur[!paste(cur$advisory_id, cur$modified) %in% paste(prev$advisory_id, prev$modified), , drop = FALSE]
  out <- rbind(prev, new)
  out <- out[order(out$advisory_id, out$first_seen, out$modified), , drop = FALSE]
  rownames(out) <- NULL
  out
}

empty_history <- function() {
  data.frame(advisory_id = character(0), modified = character(0), first_seen = character(0),
             raw_json = character(0), stringsAsFactors = FALSE)
}

#' Today's advisories plus every earlier one OSV no longer has. in_osv is 1 for
#' today's and 0 for the carried ones, and first_seen comes from the history.
carry_forward <- function(prev, adv, history) {
  adv$in_osv <- rep(1L, nrow(adv))
  if (!is.null(prev) && nrow(prev)) {
    gone <- prev[!prev$id %in% adv$id, , drop = FALSE]
    if (nrow(gone)) {
      gone$in_osv <- 0L
      adv <- rbind(adv, gone[, names(adv), drop = FALSE])
    }
  }
  first <- tapply(history$first_seen, history$advisory_id, min)
  adv$first_seen <- unname(as.character(first[adv$id]))
  adv <- adv[order(adv$id), , drop = FALSE]
  rownames(adv) <- NULL
  adv
}

#' Upstream rows for this run. Ids whose lookup failed keep the previous run's
#' rows, marked failed_kept_previous; with no previous row they get one row with
#' no vector, so the failure still shows.
carry_upstream <- function(prev, fresh, failed_ids) {
  keep <- fresh[!fresh$upstream_id %in% failed_ids, , drop = FALSE]
  if (!length(failed_ids)) return(keep)
  old <- if (is.null(prev)) fresh[0, ] else prev[prev$upstream_id %in% failed_ids, names(fresh), drop = FALSE]
  if (nrow(old)) old$lookup_status <- "failed_kept_previous"
  missing <- fresh[fresh$upstream_id %in% setdiff(failed_ids, old$upstream_id), , drop = FALSE]
  out <- rbind(keep, old, missing)
  out <- out[order(out$advisory_id, out$upstream_id), , drop = FALSE]
  rownames(out) <- NULL
  out
}

#' Reasons this run must not publish, empty when it may. prev_manifest is NULL
#' on a cold start.
publish_guard <- function(prev_manifest, advisories, history) {
  reasons <- character(0)
  if (!nrow(advisories)) reasons <- c(reasons, "no advisories parsed")
  if (!is.null(prev_manifest)) {
    prev_n <- as.integer(prev_manifest$tables$advisories %||% 0L)
    if (nrow(advisories) < prev_n) {
      reasons <- c(reasons, sprintf("advisories fell from %d to %d", prev_n, nrow(advisories)))
    }
    prev_h <- as.integer(prev_manifest$tables$advisory_history %||% 0L)
    if (nrow(history) < prev_h) {
      reasons <- c(reasons, sprintf("advisory_history fell from %d to %d rows", prev_h, nrow(history)))
    }
    prev_first <- prev_manifest$history_earliest %||% NA_character_
    now_first <- if (nrow(history)) min(history$first_seen) else NA_character_
    if (!is.na(prev_first) && (is.na(now_first) || now_first > prev_first)) {
      reasons <- c(reasons, sprintf("advisory_history lost its earliest row (%s)", prev_first))
    }
  }
  reasons
}
