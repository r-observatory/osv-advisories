test_that("export_db creates every table, and read_prev_tables reads them back", {
  path <- withr::local_tempfile(fileext = ".db")
  hist <- data.frame(advisory_id = "A", modified = "m", first_seen = "2026-10-15", raw_json = "{}",
                     stringsAsFactors = FALSE)
  export_db(path, list(advisory_history = hist))
  con <- DBI::dbConnect(RSQLite::SQLite(), path)
  expect_setequal(DBI::dbListTables(con), names(TABLE_DDL))
  DBI::dbDisconnect(con)
  back <- read_prev_tables(path)
  expect_equal(back$advisory_history$advisory_id, "A")
  expect_equal(nrow(back$advisories), 0L)
})
