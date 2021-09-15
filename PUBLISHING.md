# New version publishing instructions

Ideally it would be done by a CI action.
For now it has to be done manually.


## Release commit

- Update `CHANGELOG.md` (replace `Unpublished` with the version and the release date).
- Bump version in `umbral-pre/Cargo.toml`.
- Bump version in `umbral-pre-python/Cargo.toml`.
- Bump version in `umbral-pre-python/docs/conf.py`.
- Bump version in `umbral-pre-python/setup.py`.
- Bump version in `umbral-pre-wasm/Cargo.toml`.
- Bump version in `umbral-pre-wasm/package.template.json`.
- Tag the release commit with the version tag (in `v*.*.*` format).


## Rust crate

In `umbral-pre` dir:

- `cargo login <your_id>` (using your crates.io ID).
- `cargo publish`.

See https://doc.rust-lang.org/cargo/reference/publishing.html for more info on publishing.


## Python package

In `umbral-pre-python` dir:

- Clean `dist` (if it is not empty).
- `python setup.py sdist` (generate source distribution).
- `docker run --rm -v `pwd`/..:/io quay.io/pypa/manylinux2014_x86_64 /io/umbral-pre-python/build-wheels.sh` (generate Linux wheels).
- `twine upload dist/*`.


## NPM package

In `umbral-pre-wasm` dir:

- `rm -rf pkg`.
- `make`.
- `wasm-pack login`.
- `cd pkg`.
- `npm publish --access=public`.

See see https://rustwasm.github.io/docs/wasm-pack/tutorials/npm-browser-packages/packaging-and-publishing.html for more info on publishing.
