# New version publishing instructions

Ideally it would be done by a CI action.
For now, it has to be done manually.


## Keeping the changelog and bumping the version

For every version, list the "Changed" items first (meaning backward incompatible changes), then "Added" (new features), then "Fixed" (bug fixes, or other improvements that do not change the API/ABI).
Rust has some specifics in what is considered a breaking change; refer to https://doc.rust-lang.org/cargo/reference/semver.html for the full list.
The version number part (major/minor/patch) that is bumped should correspond to whether there is something in "Changed" or "Added" categories.


## Release commit

- Update `CHANGELOG.md` (replace `Unreleased` with the version and the release date).
- Use Python [Bumpversion](https://github.com/c4urself/bump2version/) to automatically update relevant version strings throughout the repo.
  - `bump2version <major/minor/patch> --new-version <major>.<minor>.<patch>`
- git push the commit and tag
  - `git push upstream master --tags`



## Rust crate

In `umbral-pre` dir:

- `cargo login <your_id>` (using your crates.io ID).
- `cargo publish`.

See https://doc.rust-lang.org/cargo/reference/publishing.html for more info on publishing.


## Python package

Gitub Actions are configured to take care of this automatically.
- Can be [manually triggered here](https://github.com/nucypher/rust-umbral/actions/workflows/wheels.yml) (manual mode has not been tested)

## NPM package

In `umbral-pre-wasm` dir:

- `rm -rf pkg`.
- `make`.
- `wasm-pack login`.
- `cd pkg`.
- `npm publish --access=public`.

See see https://rustwasm.github.io/docs/wasm-pack/tutorials/npm-browser-packages/packaging-and-publishing.html for more info on publishing.
