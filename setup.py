"""Setup configuration for gcp-secrets-manager package."""
from setuptools import setup, find_packages

# Leer el README para la descripción larga
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Leer requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="gcp-secrets-manager",
    version="0.1.0",
    author="cloud department",
    author_email="cloud department",
    description="Gestor profesional de secretos para Google Cloud Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/FloresLozano/gcp_secrets_manager_pruebas.git",
    project_urls={
        "Bug Tracker": "https://github.com/FloresLozano/gcp_secrets_manager_pruebas.git/issues",
        "Documentation": "https://gcp-secrets-manager.readthedocs.io",
        "Source Code": "https://github.com/FloresLozano/gcp_secrets_manager_pruebas.git",
    },
    packages=find_packages(exclude=["tests*", "examples*", "docs*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "black",
            "mypy",
        ]
    },
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "gcp-secrets-cli=gcp_secrets_manager.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)