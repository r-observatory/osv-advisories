# scripts/state.R: what carries over from the previous release. Pure.

#' advisory_history with a row added for every (id, modified) not seen before,
#' stamped with today. prev may be NULL (cold start).
merge_history <- function(prev, adv, today) {
  prev <- if (is.null(prev)) empty_history() else prev[, names(empty_history()), drop = FALSE]
  if (!nrow(adv)) return(prev)
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

#' Upstream rows for this run. A failed lookup keeps the previous run's row for
#' the same advisory and upstream id when that row carries a vector, marked
#' failed_kept_previous; otherwise the failed row stays, so the failure shows.
carry_upstream <- function(prev, fresh, failed_ids) {
  if (!length(failed_ids)) return(fresh)
  is_failed <- fresh$upstream_id %in% failed_ids
  key <- function(d) paste(d$advisory_id, d$upstream_id, sep = "\r")
  old <- if (is.null(prev)) fresh[0, ] else prev[, names(fresh), drop = FALSE]
  old <- old[old$lookup_status %in% c("ok", "failed_kept_previous") &
               key(old) %in% key(fresh[is_failed, , drop = FALSE]), , drop = FALSE]
  if (nrow(old)) old$lookup_status <- "failed_kept_previous"
  out <- rbind(fresh[!is_failed | !key(fresh) %in% key(old), , drop = FALSE], old)
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

#' Reasons to refuse on today's parsed advisories, before anything carries
#' forward. prev_manifest is NULL on a cold start.
parse_guard <- function(prev_manifest, parsed_n) {
  if (parsed_n == 0L) return("no advisories parsed")
  if (is.null(prev_manifest)) return(character(0))
  prev_n <- prev_manifest$counts$advisories_parsed %||%
    ((prev_manifest$tables$advisories %||% 0L) - (prev_manifest$counts$advisories_not_in_osv %||% 0L))
  prev_n <- as.integer(prev_n)
  tolerance <- max(PARSED_DROP_MIN, floor(PARSED_DROP_FRACTION * prev_n))
  if (parsed_n < prev_n - tolerance) {
    return(sprintf("advisories parsed fell from %d to %d", prev_n, parsed_n))
  }
  character(0)
}

#' Reasons to refuse on the CRAN version list and the tarball matches.
versions_guard <- function(prev_manifest, versions_read, affected_in_tarballs) {
  reasons <- character(0)
  if (versions_read == 0L) return("no CRAN versions read from cran-archive")
  if (!is.null(prev_manifest)) {
    prev_v <- prev_manifest$counts$versions_read
    if (!is.null(prev_v) && versions_read < VERSIONS_FLOOR_FRACTION * prev_v) {
      reasons <- c(reasons, sprintf("CRAN versions read fell from %d to %d", as.integer(prev_v), versions_read))
    }
    prev_a <- prev_manifest$counts$affected_in_tarballs
    if (affected_in_tarballs == 0L && !is.null(prev_a) && prev_a > 0L) {
      reasons <- c(reasons, "no affected version matched a tarball (was above 0)")
    }
  }
  reasons
}
