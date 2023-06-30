from setuptools import setup, find_packages


with open("README.md", "r") as readme_file:
    long_desc = readme_file.read()

setup(
    author="Inuits",
    author_email="developers@inuits.eu",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
    description="Module for securing API endpoints based on policies.",
    install_requires=[
        "Authlib>=1.2.0",
        "cffi>=1.15.1",
        "click>=8.1.3",
        "cryptography>=40.0.2",
        "MarkupSafe>=2.1.2",
        "pycparser>=2.21",
        "requests>=2.28.2",
        "Werkzeug>=2.2.3",
    ],
    license="GPLv2",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    name="inuits_policy_based_auth",
    packages=find_packages(exclude=["tests"]),
    provides=["inuits_policy_based_auth"],
    version="4.0.0",
)
