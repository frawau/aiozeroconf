#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from distutils.core import setup

version = "0.1.3"

setup(name='aiozeroconf',
    packages=['aiozeroconf'],
    version=version,
    author='Paul Scott-Murphy, William McBrine, Jakub Stasiak, François Wautier',
    author_email='francois@wautier.eu',
    description='Pure Python Multicast DNS Service Discovery Library for asyncio '
    '(Bonjour/Avahi compatible)',
    url='https://github.com/frawau/aiozeroconf',
    download_url='https://github.com/frawau/aiozeroconf/archive/'+version+'.tar.gz',
    platforms=['unix', 'linux', 'osx'],
    license='LGPL',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython'
    ],
    keywords=[
        'Bonjour', 'Avahi', 'Zeroconf', 'Multicast DNS', 'Service Discovery',
        'mDNS', 'asyncio',
    ],
    install_requires=[
        'netifaces',
    ],
)
