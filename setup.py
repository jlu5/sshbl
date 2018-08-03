#!/usr/bin/env python3

from setuptools import setup

setup(name='sshbl',
     version='0.1',
     author='James Lu',
     author_email='james@overdrivenetworks.com',
     description='SSH Banner Blacklisting Suite',
     license="GPL",
     url="https://github.com/jlu5/sshbl",
     packages=['sshbl'],
     entry_points={'console_scripts': [
        'bannergrabber = sshbl.bannergrabber:main',
         ]}
)
