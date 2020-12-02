# Python bindings for `umbral-pre`

[![pypi package][pypi-image]][pypi-link] ![License][pypi-license-image]

This repo contains the Python bindings for the [main Rust project][umbral-pre].


## Build

You will need to have `setuptools-rust` installed. Then, for development you can just do `pip install -e .` as usual.

Building Linux wheels must be done via Docker (makefile under construction).
```
$ docker pull quay.io/pypa/manylinux2014_x86_64
$ docker run --rm -v `pwd`/..:/io quay.io/pypa/manylinux2014_x86_64 /io/umbral-pre-python/build-wheels.sh
```

[pypi-image]: https://img.shields.io/pypi/v/umbral-pre
[pypi-link]: https://pypi.org/project/umbral-pre/
[pypi-license-image]: https://img.shields.io/pypi/l/umbral-pre
[umbral-pre]: https://github.com/nucypher/rust-umbral/tree/master/umbral-pre
