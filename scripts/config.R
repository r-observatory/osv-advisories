# scripts/config.R: constants for the osv-advisories pipeline.
OSV_BUCKET        <- "https://osv-vulnerabilities.storage.googleapis.com"
OSV_API           <- "https://api.osv.dev/v1/vulns"
# Fetched only when OSV's ecosystems.txt lists them. Only CRAN versions are
# expanded; Bioconductor advisories are stored with their ranges alone.
ECOSYSTEMS_WANTED <- c("CRAN", "Bioconductor")
EXPAND_ECOSYSTEMS <- c("CRAN")
PUBLISH_REPO      <- "r-observatory/osv-advisories"
ARCHIVE_REPO      <- "r-observatory/cran-archive"
ARCHIVE_DB        <- "cran-archive.db"
DB_FILENAME       <- "osv-advisories.db"
LICENSE_ASSET     <- "ADVISORY-DATA-LICENSE.txt"
SCRIPT_VERSION    <- "1.0.0"
HTTP_TRIES        <- 4L
HTTP_WAIT_S       <- 5
# Connect and total limits per request; the total leaves room for the CRAN zip.
HTTP_CONNECT_TIMEOUT_S <- 20
HTTP_TIMEOUT_S    <- 300
# Guards on a run's inputs. Fewer parsed advisories than last time by more than
# max(PARSED_DROP_MIN, floor(PARSED_DROP_FRACTION * last)) stops the run, and so
# does a version list below VERSIONS_FLOOR_FRACTION of the last one.
PARSED_DROP_FRACTION   <- 0.1
PARSED_DROP_MIN        <- 1L
VERSIONS_FLOOR_FRACTION <- 0.9

raw_zip_name <- function(ecosystem) sprintf("osv-%s-all.zip", ecosystem)
