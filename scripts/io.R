# scripts/io.R: the network and GitHub side, injected into run_update().

#' HTTP status of a release tag, from the first line `gh api -i` prints. 200
#' means it exists, 404 that it does not; NA when gh printed no status line.
#' gh release view cannot tell a 403 from a 404, so it is not used here.
gh_release_status <- function(repo, tag, runner = system2) {
  out <- suppressWarnings(runner("gh", c("api", "-i", sprintf("repos/%s/releases/tags/%s", repo, tag)),
                                 stdout = TRUE, stderr = FALSE))
  first <- if (length(out)) out[[1]] else ""
  m <- regmatches(first, regexec("^HTTP/[0-9.]+ ([0-9]{3})", first))[[1]]
  if (length(m) == 2L) as.integer(m[[2]]) else NA_integer_
}

#' Download one asset of a release into dir and return its path. Throws when gh
#' fails or the file is missing or empty.
gh_download_asset <- function(repo, tag, asset, dir, runner = system2) {
  st <- suppressWarnings(runner("gh", c("release", "download", tag, "--repo", repo,
                                        "--pattern", asset, "--dir", dir, "--clobber"),
                                stdout = FALSE, stderr = FALSE))
  path <- file.path(dir, asset)
  if (!identical(as.integer(st), 0L) || !file.exists(path) || file.size(path) == 0) {
    stop(sprintf("could not download %s from %s@%s", asset, repo, tag))
  }
  path
}

#' GET with retries. Returns list(status, body); status 0 when every try failed
#' without an HTTP answer.
http_get <- function(url, tries = HTTP_TRIES, wait = HTTP_WAIT_S, fetch = curl::curl_fetch_memory) {
  last <- list(status = 0L, body = raw(0))
  for (k in seq_len(tries)) {
    h <- curl::new_handle(connecttimeout = HTTP_CONNECT_TIMEOUT_S, timeout = HTTP_TIMEOUT_S)
    res <- tryCatch(fetch(url, handle = h), error = function(e) NULL)
    if (!is.null(res)) {
      last <- list(status = as.integer(res$status_code), body = res$content)
      if (last$status < 500L && last$status != 429L) return(last)
    }
    if (k < tries) Sys.sleep(wait * k)
  }
  last
}

#' list(status, record) for an OSV record response. A 200 body that does not
#' parse counts as failed.
parse_vuln_response <- function(status, body) {
  if (status == 200L) {
    rec <- tryCatch(jsonlite::parse_json(rawToChar(body), simplifyVector = FALSE), error = function(e) NULL)
    if (is.null(rec)) return(list(status = "failed", record = NULL))
    return(list(status = "ok", record = rec))
  }
  if (status == 404L) return(list(status = "not_in_osv", record = NULL))
  list(status = "failed", record = NULL)
}

#' The real providers. Each throws on a failure the run must not get past.
default_io <- function() {
  list(
    ecosystems = function() {
      r <- http_get(paste0(OSV_BUCKET, "/ecosystems.txt"))
      if (r$status != 200L) stop("ecosystems.txt: HTTP ", r$status)
      rawToChar(r$body)
    },
    osv_zip = function(ecosystem, dest) {
      r <- http_get(sprintf("%s/%s/all.zip", OSV_BUCKET, utils::URLencode(ecosystem)))
      if (r$status != 200L || !length(r$body)) stop(ecosystem, "/all.zip: HTTP ", r$status)
      writeBin(r$body, dest)
      dest
    },
    prev_state = function() {
      st <- gh_release_status(PUBLISH_REPO, "current")
      if (identical(st, 404L)) return(list(status = "cold_start"))
      if (!identical(st, 200L)) stop("release current: status ", st)
      dir <- tempfile("prev-"); dir.create(dir)
      list(status = "ok",
           db = gh_download_asset(PUBLISH_REPO, "current", DB_FILENAME, dir),
           manifest = jsonlite::read_json(gh_download_asset(PUBLISH_REPO, "current", "manifest.json", dir)))
    },
    archive_versions = function() {
      dir <- tempfile("archive-"); dir.create(dir)
      db <- gh_download_asset(ARCHIVE_REPO, "current", ARCHIVE_DB, dir)
      con <- DBI::dbConnect(RSQLite::SQLite(), db)
      on.exit(DBI::dbDisconnect(con), add = TRUE)
      DBI::dbGetQuery(con, "SELECT DISTINCT package, version FROM cran_tarballs")
    },
    osv_vuln = function(id) {
      r <- http_get(paste0(OSV_API, "/", utils::URLencode(id)))
      parse_vuln_response(r$status, r$body)
    },
    now = function() Sys.time()
  )
}
