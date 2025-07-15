import os
import sys
sys.path.insert(0, os.path.abspath('../src'))


project = 'Contacts API'
copyright = '2025, Ruslana'
author = 'Ruslana'

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.napoleon']

templates_path = ['_templates']
exclude_patterns = []


html_theme = 'alabaster'
html_static_path = ['_static']
