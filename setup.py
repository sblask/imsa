#!/usr/bin/env python

from distutils.core import setup
import os

requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')

with open(requirements_path) as file_object:
    requirements = file_object.readlines()

setup(
    name='imsa',
    version='1.0',
    author='Sebastian Blask',
    description='Instance Metadata Service for Authentication',
    py_modules=['imsa'],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'imsa=imsa:main',
        ]
    }
)
