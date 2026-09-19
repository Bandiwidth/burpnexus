from setuptools import setup, find_packages
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Read version from the package __init__ file
version = "1.0.0"
with open(ROOT / "burpmd/__init__.py", "r") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.strip().split("=")[1].strip().strip('"').strip("'")
            break

# Read long description from README
with open(ROOT / "README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="burpmd-parser",
    version=version,
    author="BurpNexus contributors",
    author_email="",
    description="Burp Suite XML export parser and local security-analysis artifact generator.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Bandiwidth/burpnexus",
    project_urls={
        "Source": "https://github.com/Bandiwidth/burpnexus",
        "Issues": "https://github.com/Bandiwidth/burpnexus/issues",
    },
    license="MIT",
    include_package_data=True,
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "burpmd=burpmd.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.10",
    install_requires=["defusedxml>=0.7.1,<0.8"],
    extras_require={"rag": ["chromadb>=1.5.9,<2"]},
    keywords="burp burpsuite security pentesting xml parser markdown json ai copilot",
)
