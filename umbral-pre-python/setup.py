from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="umbral_pre",
    version="0.0.1",
    rust_extensions=[RustExtension("umbral_pre._umbral", binding=Binding.PyO3)],
    packages=["umbral_pre"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)
