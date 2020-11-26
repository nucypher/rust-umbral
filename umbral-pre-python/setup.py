from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="umbral",
    version="0.0.1",
    rust_extensions=[RustExtension("_umbral.umbral", binding=Binding.PyO3)],
    packages=["umbral"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)
