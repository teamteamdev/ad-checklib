"""adchecklib installer"""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="adchecklib",
    version="0.2.2",
    author="Nikita Sychev",
    author_email="team@teamteam.dev",
    description="Attack-Defense checker library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ugractf/ad-checklib",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ],
    python_requires=">=3.6"
)
