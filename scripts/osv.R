# scripts/osv.R: read OSV records into flat tables. Pure: no network.

`%||%` <- function(a, b) if (is.null(a)) b else a

#' The ecosystem names in OSV's ecosystems.txt, one per line.
parse_ecosystems <- function(text) {
  lines <- trimws(unlist(strsplit(text, "\n", fixed = TRUE)))
  lines[nzchar(lines)]
}

#' The ecosystems to download: the wanted ones OSV lists, in wanted order.
ecosystems_to_fetch <- function(listed, wanted = ECOSYSTEMS_WANTED) {
  wanted[wanted %in% listed]
}

#' Every *.json file under dir as list(record, raw), sorted by file name.
read_osv_dir <- function(dir) {
  files <- sort(list.files(dir, pattern = "\\.json$", full.names = TRUE))
  lapply(files, function(f) {
    raw <- paste(readLines(f, warn = FALSE, encoding = "UTF-8"), collapse = "\n")
    list(record = jsonlite::parse_json(raw, simplifyVector = FALSE), raw = raw)
  })
}

.json_or_na <- function(x) {
  if (is.null(x) || !length(x)) NA_character_
  else as.character(jsonlite::toJSON(x, auto_unbox = TRUE))
}

#' One row per advisory. in_osv and first_seen are filled in by state.R.
osv_advisories_df <- function(items, ecosystem) {
  rows <- lapply(items, function(it) {
    r <- it$record
    data.frame(
      id = r$id, ecosystem = ecosystem,
      summary = r$summary %||% NA_character_, details = r$details %||% NA_character_,
      published = r$published %||% NA_character_, modified = r$modified %||% NA_character_,
      withdrawn = r$withdrawn %||% NA_character_,
      upstream = .json_or_na(unlist(r$upstream)) %||% NA_character_,
      aliases = .json_or_na(unlist(r$aliases)), related = .json_or_na(unlist(r$related)),
      credits = .json_or_na(r$credits), severity = .json_or_na(r$severity),
      refs = .json_or_na(r$references), schema_version = r$schema_version %||% NA_character_,
      raw_json = it$raw, stringsAsFactors = FALSE)
  })
  if (!length(rows)) return(empty_advisories())
  do.call(rbind, rows)
}

empty_advisories <- function() {
  data.frame(id = character(0), ecosystem = character(0), summary = character(0),
             details = character(0), published = character(0), modified = character(0),
             withdrawn = character(0), upstream = character(0), aliases = character(0),
             related = character(0), credits = character(0), severity = character(0),
             refs = character(0), schema_version = character(0), raw_json = character(0),
             stringsAsFactors = FALSE)
}

#' Turn one OSV range's ordered events into intervals. An "introduced" opens an
#' interval, "fixed" or "last_affected" closes it, and an interval still open at
#' the end runs to the newest version. "limit" applies to the whole range.
events_to_intervals <- function(events) {
  out <- list(); open <- NULL; limit <- NA_character_
  for (e in events) {
    if (!is.null(e$limit)) limit <- as.character(e$limit)
    if (!is.null(e$introduced)) {
      if (!is.null(open)) out[[length(out) + 1L]] <- c(open, fixed = NA, last_affected = NA)
      open <- c(introduced = as.character(e$introduced))
    } else if (!is.null(e$fixed) && !is.null(open)) {
      out[[length(out) + 1L]] <- c(open, fixed = as.character(e$fixed), last_affected = NA)
      open <- NULL
    } else if (!is.null(e$last_affected) && !is.null(open)) {
      out[[length(out) + 1L]] <- c(open, fixed = NA, last_affected = as.character(e$last_affected))
      open <- NULL
    }
  }
  if (!is.null(open)) out[[length(out) + 1L]] <- c(open, fixed = NA, last_affected = NA)
  lapply(out, function(iv) c(iv, limit_ver = limit))
}

#' One row per advisory, affected package and interval.
osv_ranges_df <- function(items, ecosystem) {
  rows <- list()
  for (it in items) {
    r <- it$record
    for (a in r$affected %||% list()) {
      pkg <- a$package$name %||% NA_character_
      seq <- 0L
      for (rg in a$ranges %||% list()) {
        for (iv in events_to_intervals(rg$events %||% list())) {
          seq <- seq + 1L
          rows[[length(rows) + 1L]] <- data.frame(
            advisory_id = r$id, ecosystem = ecosystem, package = pkg,
            purl = a$package$purl %||% NA_character_,
            source_url = a$database_specific$source %||% NA_character_,
            range_seq = seq, range_type = rg$type %||% NA_character_,
            introduced = unname(iv[["introduced"]]), fixed = unname(iv[["fixed"]]),
            last_affected = unname(iv[["last_affected"]]), limit_ver = unname(iv[["limit_ver"]]),
            stringsAsFactors = FALSE)
        }
      }
    }
  }
  if (!length(rows)) {
    return(data.frame(advisory_id = character(0), ecosystem = character(0), package = character(0),
                      purl = character(0), source_url = character(0), range_seq = integer(0),
                      range_type = character(0), introduced = character(0), fixed = character(0),
                      last_affected = character(0), limit_ver = character(0), stringsAsFactors = FALSE))
  }
  do.call(rbind, rows)
}

#' The versions OSV lists by name, one row per advisory, package and version.
osv_listed_df <- function(items, ecosystem) {
  rows <- list()
  for (it in items) {
    for (a in it$record$affected %||% list()) {
      vs <- unlist(a$versions %||% list())
      if (length(vs)) {
        rows[[length(rows) + 1L]] <- data.frame(
          advisory_id = it$record$id, ecosystem = ecosystem,
          package = a$package$name %||% NA_character_, version = as.character(vs),
          stringsAsFactors = FALSE)
      }
    }
  }
  if (!length(rows)) {
    return(data.frame(advisory_id = character(0), ecosystem = character(0),
                      package = character(0), version = character(0), stringsAsFactors = FALSE))
  }
  unique(do.call(rbind, rows))
}

#' Every distinct upstream id across the advisories, sorted.
upstream_ids <- function(adv) {
  ids <- unlist(lapply(adv$upstream, function(j) if (is.na(j)) character(0) else jsonlite::fromJSON(j)))
  sort(unique(as.character(ids)))
}
