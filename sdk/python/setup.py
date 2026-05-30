from setuptools import setup, find_packages

setup(
    name="crovia-seal",
    version="0.1.0",
    description="Verify Crovia AI seals — Ed25519 cryptographic provenance for AI outputs",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Crovia Research",
    author_email="security@croviatrust.com",
    url="https://croviatrust.com",
    project_urls={
        "Documentation": "https://croviatrust.com/seal",
        "Source": "https://github.com/croviatrust/crovia-seal",
        "Verify": "https://croviatrust.com/check.html",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["PyNaCl>=1.5.0"],
    entry_points={
        "console_scripts": [
            "crovia-verify=crovia_seal.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="crovia seal ai provenance ed25519 verification cryptography transparency",
)
