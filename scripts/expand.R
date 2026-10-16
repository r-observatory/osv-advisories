# scripts/expand.R: which known versions each advisory affects. Pure.

#' package_version for each string, NA where R cannot parse it.
safe_pv <- function(x) {
  out <- lapply(as.character(x), function(s) {
    if (is.na(s) || !nzchar(s)) return(NULL)
    tryCatch(package_version(s), error = function(e) NULL)
  })
  out
}

#' TRUE where version v (a package_version) falls inside the interval. An
#' introduced of "0" means from the first version. Exactly one of fixed and
#' last_affected may be set; neither means the interval is still open.
version_in_interval <- function(v, introduced, fixed, last_affected) {
  lo <- if (identical(introduced, "0")) NULL else safe_pv(introduced)[[1]]
  if (!identical(introduced, "0") && is.null(lo)) return(NA)
  if (!is.null(lo) && v < lo) return(FALSE)
  if (!is.na(fixed)) {
    hi <- safe_pv(fixed)[[1]]
    if (is.null(hi)) return(NA)
    return(v < hi)
  }
  if (!is.na(last_affected)) {
    hi <- safe_pv(last_affected)[[1]]
    if (is.null(hi)) return(NA)
    return(v <= hi)
  }
  TRUE
}

EXPANDABLE_RANGE_TYPES <- c("ECOSYSTEM", "SEMVER")

#' Affected (package, version, advisory) rows for one ecosystem.
#'
#' ranges:   osv_ranges_df() rows
#' listed:   osv_listed_df() rows
#' versions: data.frame(package, version), every known version of every package
#' withdrawn_ids: advisories that must produce no rows
#'
#' Returns list(rows, unparsed, listed_missing, range_not_listed). unparsed counts
#' interval bounds or known versions R could not parse; listed_missing counts
#' versions OSV lists that are not in `versions`; range_not_listed counts rows the
#' ranges found that OSV's own list lacks.
expand_affected <- function(ranges, listed, versions, withdrawn_ids = character(0)) {
  ranges <- ranges[!ranges$advisory_id %in% withdrawn_ids &
                   ranges$range_type %in% EXPANDABLE_RANGE_TYPES, , drop = FALSE]
  listed <- listed[!listed$advisory_id %in% withdrawn_ids, , drop = FALSE]
  versions <- unique(versions[, c("package", "version")])
  unparsed <- 0L
  hits <- list()
  for (i in seq_len(nrow(ranges))) {
    rg <- ranges[i, ]
    vs <- versions$version[versions$package == rg$package]
    pvs <- safe_pv(vs)
    for (j in seq_along(vs)) {
      if (is.null(pvs[[j]])) { unparsed <- unparsed + 1L; next }
      inside <- version_in_interval(pvs[[j]], rg$introduced, rg$fixed, rg$last_affected)
      if (is.na(inside)) { unparsed <- unparsed + 1L; break }
      if (inside) hits[[length(hits) + 1L]] <- c(rg$advisory_id, rg$ecosystem, rg$package, vs[[j]])
    }
  }
  # paste() turns zero-length input plus "" into one string, so guard it.
  key <- function(a, p, v) if (!length(p)) character(0) else paste(a, p, v, sep = "\r")
  from_range <- if (length(hits)) {
    m <- do.call(rbind, hits)
    unique(data.frame(advisory_id = m[, 1], ecosystem = m[, 2], package = m[, 3],
                      version = m[, 4], stringsAsFactors = FALSE))
  } else listed[0, ]
  rk <- key(from_range$advisory_id, from_range$package, from_range$version)
  lk <- key(listed$advisory_id, listed$package, listed$version)
  known <- key("", versions$package, versions$version)
  all_rows <- unique(rbind(from_range, listed))
  ak <- key(all_rows$advisory_id, all_rows$package, all_rows$version)
  all_rows$basis <- ifelse(ak %in% rk & ak %in% lk, "both", ifelse(ak %in% rk, "range", "listed"))
  all_rows$in_tarballs <- as.integer(key("", all_rows$package, all_rows$version) %in% known)
  all_rows <- all_rows[order(all_rows$advisory_id, all_rows$package, all_rows$version), , drop = FALSE]
  rownames(all_rows) <- NULL
  list(rows = all_rows,
       unparsed = unparsed,
       listed_missing = sum(!key("", listed$package, listed$version) %in% known),
       range_not_listed = sum(!rk %in% lk))
}
