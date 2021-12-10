# New version publishing instructions

Ideally it would be done by a CI action.
For now it has to be done manually.


## Release commit

- Update `CHANGELOG.md` (replace `Unreleased` with the version and the release date).
- Use Python [Bumpversion](https://github.com/c4urself/bump2version/) to autmoatically update relevant version strings throughout the repo.
  - `bump2version minor --current-version <major>.<minor>.<patch>`
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
