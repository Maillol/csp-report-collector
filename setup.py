#!/usr/bin/env python3

from setuptools import setup
from csp_report_collector import __version__

setup(
    name="csp-report-collector",
    version=__version__,
    description="Content-Security-Policy Report Collector",
    long_description="A Python Flask app to receive and store Content-Security-Policy reports",
    author="Andy Dustin",
    author_email="andy.dustin@gmail.com",
    url="https://github.com/finalduty/csp-report-collector/",
    python_requires=">=3.6",
    install_requires=[
        "click==8.0.3; python_version >= '3.6'",
        "configparser==5.2.0",
        "flask==2.0.2",
        "gevent==21.12.0",
        "greenlet==1.1.2; platform_python_implementation == 'CPython'",
        "gunicorn==20.1.0",
        "itsdangerous==2.0.1; python_version >= '3.6'",
        "jinja2==3.0.3; python_version >= '3.6'",
        "markupsafe==2.0.1; python_version >= '3.6'",
        "pymongo==4.0.1",
        "setuptools==60.8.2; python_version >= '3.7'",
        "werkzeug==2.0.3; python_version >= '3.6'",
        "zope.event==4.5.0",
        "zope.interface==5.4.0; python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2, 3.3, 3.4'",
    ],
    dependency_links=[],
    scripts=["csp_report_collector.py"],
    package_data={'': ['settings.conf.example']},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application"
    ],
)
