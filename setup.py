from setuptools import setup, find_packages

setup(
    name="zero-trust-github-guard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-dotenv",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "zero-trust-guard=zero_trust_guard.main:main",
        ],
    },
    author="Informant254",
    description="Advanced security scanner for detecting exposed API keys and hardening GitHub account permissions.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Informant254/Zero-Trust-GitHub-Guard",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
