from setuptools import setup, Extension
from Cython.Build import cythonize
import sys

# Compiler directives for optimization
compiler_directives = {
    'language_level': "3",
    'boundscheck': False,
    'wraparound': False,
    'cdivision': True,
    'embedsignature': True,
}

# Extensions to build
extensions = [
    Extension("network_utils", ["network_utils.pyx"]),
    Extension("data_utils", ["data_utils.pyx"]),
]

setup(
    name='spiffy-fast',
    version='1.0.0',
    description='High-performance Cython modules for Spiffy',
    ext_modules=cythonize(
        extensions,
        compiler_directives=compiler_directives,
        annotate=True,  # Generate HTML annotation files
    ),
    zip_safe=False,
)
