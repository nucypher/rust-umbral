from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="umbral_pre",
    description="Implementation of Umbral proxy reencryption algorithm",
    version="0.5.1",
    author="Bogdan Opanchuk",
    author_email="bogdan@opanchuk.net",
    url="https://github.com/nucypher/rust-umbral/tree/master/umbral-pre-python",
    rust_extensions=[RustExtension("umbral_pre._umbral", binding=Binding.PyO3)],
    packages=["umbral_pre"],
    package_data = {
        'umbral_pre': ['py.typed', '__init__.pyi'],
    },
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Rust",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security :: Cryptography",
    ],
)
