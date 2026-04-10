from setuptools import setup, find_packages

setup(
    name="chunkvault",
    version="0.1.0",
    description="Chunk-encrypted cloud storage with random access and role-based key distribution",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "flask>=3.0.0",
        "flask-jwt-extended>=4.6.0",
        "cryptography>=42.0.0",
        "bcrypt>=4.1.0",
        "click>=8.1.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "chunkvault=client.cli:cli",
            "chunkvault-server=server.app:main",
        ],
    },
)
