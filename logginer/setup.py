import setuptools
from setuptools import setup
metadata = {'name': 'logging',
            'packages': setuptools.find_packages(),
            'include_package_data': True,
            'version': '0.1',
            'long_description': '',
            'python_requires': '>=3.10',
            'install_requires': []}



setup(**metadata)
