from setuptools import setup, find_packages

# Read version from the package __init__ file
version = "1.0.0"
with open("burpmd/__init__.py", "r") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.strip().split("=")[1].strip().strip('"').strip("'")
            break

# Read long description from README
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="burpmd-parser",
    version=version,
    author="BurpMD Parser Pro",
    author_email="",
    description="A professional Burp Suite XML export parser for AI-driven security analysis.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/user/burpmd-parser-pro",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "burpmd=burpmd.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    keywords="burp burpsuite security pentesting xml parser markdown json ai copilot",
)
