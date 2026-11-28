# Release process

`authent` publishes the root module and the `redis/` module in sequence with
the same version number. `integration/` is for tests and is not published.
The current release workflow supports `v0.x.y` versions. Never move a
published Go module tag; publish a new version if a correction is needed.

## Regular pull requests

Add a short release note in English for user-facing changes. Internal-only
changes do not need one.

```sh
go install github.com/miniscruff/changie@v1.26.0
changie new
```

Choose Added, Changed, Fixed, or Security, and include the generated file in
`.changes/unreleased/` in the pull request. Do not assign a version yet.

## 1. Prepare the root module

1. Choose the next `v0.x.y` version based on the public API changes and fixes.
2. Collect the release notes into a versioned file and `CHANGELOG.md`.

   ```sh
   changie batch v0.2.0  # Replace with the actual version
   changie merge
   ```

3. Do not update the root module version in `redis/go.mod` in this pull request.
   The Redis consumer test cannot resolve a root version that is not yet
   published.
4. Review the new `CHANGELOG.md` entry and merge the pull request into `main`
   after CI passes.

## 2. Publish the root module

Open **Actions → Release → Run workflow** on GitHub. Select `main`, set
`phase` to `core`, and enter the same `v0.x.y` version used in the preparation
pull request. The workflow checks the version and changelog, runs the existing
CI, then creates the `v0.x.y` tag and GitHub Release. It does not create the
`redis/` tag yet.

If the tag is created but creating the GitHub Release fails, **rerun the same
workflow**. It retries Release creation without moving the tag.

## 3. Prepare the Redis module

Set the required root module version in `redis/go.mod` to the version just
published. Keep the local `replace` directive used for development. Run
`go mod tidy` in both nested modules and include any `integration/go.mod`
changes in the pull request.

```sh
(cd redis && go mod edit -require=github.com/tohshi/authent@v0.1.0 && go mod tidy)
(cd integration && go mod tidy)
bash .github/scripts/check-redis-consumer.sh
```

Replace the example version with the current release version. Confirm that
the Redis consumer test can fetch the published root module, then merge the
pull request into `main` after CI passes.

## 4. Publish the Redis module

Open **Actions → Release → Run workflow** again. Select `main`, set `phase` to
`redis`, and enter the same `v0.x.y` version. After the existing CI passes,
the workflow creates `redis/v0.x.y` at the current commit and adds the Redis
tag to the root GitHub Release. The root and Redis tags point to different
commits.

If the tag is created but updating the GitHub Release fails, **rerun the same
workflow**. It retries the Release update without moving the tag.

## Verify the published modules

Fetch both published versions from a fresh temporary directory.

```sh
release_check_dir=$(mktemp -d)
cd "$release_check_dir"
go mod init example.com/authent-release-check
GOPROXY=proxy.golang.org go get github.com/tohshi/authent@v0.1.0 github.com/tohshi/authent/redis@v0.1.0
```

Replace the example versions with the current release version. If the Go
proxy has not picked up the tags yet, retry the command after a short wait.
Once both modules resolve, check the GitHub Release notes and both tags.
