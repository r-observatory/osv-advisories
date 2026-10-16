# The workflow is where untested shell lives, so pin the lines that matter.
.update_yml <- function() {
  readLines(testthat::test_path("..", "..", ".github", "workflows", "update.yml"))
}

test_that("the schedule runs after cran-archive and the entrypoint gets the tested arguments", {
  wf <- paste(.update_yml(), collapse = "\n")
  expect_match(wf, 'cron: "0 6 * * *"', fixed = TRUE)
  expect_match(wf, "Rscript scripts/update.R out\n", fixed = TRUE)
  expect_match(wf, "Rscript tests/testthat.R", fixed = TRUE)
})

test_that("both release steps branch on the HTTP status, never on gh release view", {
  wf <- .update_yml()
  code <- wf[!grepl("^\\s*#", wf)]
  expect_false(any(grepl("gh release view", code, fixed = TRUE)))
  expect_equal(sum(grepl("gh api -i \"repos/$GITHUB_REPOSITORY/releases/tags/", wf, fixed = TRUE)), 2L)
  expect_equal(sum(grepl("^\\s+404\\)", wf)), 2L)
  expect_equal(sum(grepl("^\\s+200\\)", wf)), 2L)
  expect_equal(sum(grepl("exit 1 ;;", wf, fixed = TRUE)), 2L)
})

test_that("publish uploads all four assets and the backup never becomes latest", {
  wf <- paste(.update_yml(), collapse = "\n")
  for (a in c("osv-advisories.db", "manifest.json", "osv-CRAN-all.zip", "ADVISORY-DATA-LICENSE.txt")) {
    expect_equal(lengths(regmatches(wf, gregexpr(paste0("out/", a), wf, fixed = TRUE))), 2L, info = a)
  }
  expect_match(wf, 'TAG="backup-$(date -u +%Y-%m)"', fixed = TRUE)
  expect_match(wf, 'gh release create "$TAG" --latest=false', fixed = TRUE)
  backup <- grep("- name: Monthly backup release", .update_yml(), fixed = TRUE)
  publish <- grep('- name: Publish to the "current" release', .update_yml(), fixed = TRUE)
  expect_gt(backup, publish)
})

test_that("the keepalive job exists and commits last-updated.txt", {
  wf <- paste(.update_yml(), collapse = "\n")
  expect_match(wf, "keepalive:", fixed = TRUE)
  expect_match(wf, "git add last-updated.txt", fixed = TRUE)
})
