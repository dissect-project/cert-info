"""
cert-info.
Analyze digital certificates of publicly assessible domains.
Verify leaf certificates and the remaining certificate chain.
"""

# app
from .analyzer import *

# main package info
__title__ = 'cert-info'
__version__ = '0.0.1'
__author__ = 'Diogo Ribeiro'
__license__ = 'GNU GPL v3.0'


# version synonym
VERSION = __version__
