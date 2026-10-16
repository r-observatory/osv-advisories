library(testthat)
for (f in c("config.R", "osv.R", "expand.R", "cvss.R", "state.R", "export.R", "io.R", "update.R")) {
  source(file.path("scripts", f))
}
test_dir("tests/testthat", stop_on_failure = TRUE)
