#!/bin/bash
set -ex

curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain stable -y
export PATH="$HOME/.cargo/bin:$PATH"

cd /io/umbral-pre-python

for PYBIN in /opt/python/cp{36,37,38,39}*/bin; do
    rm -rf build
    "${PYBIN}/pip" install -U setuptools wheel setuptools-rust
    "${PYBIN}/python" setup.py bdist_wheel
done

for whl in dist/*.whl; do
    auditwheel repair "$whl" -w dist/
done

# PyPI only wants `manylinux`
rm dist/*-linux_x86_64.whl
