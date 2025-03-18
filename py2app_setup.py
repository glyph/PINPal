"""
To build the macOS application::

    $ python py2app_setup.py py2app
"""
"""
stub for invoking py2app
"""

from setuptools import setup
from encrust_setup import description

setup(**description.setupOptions())
