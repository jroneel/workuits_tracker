from pathlib import Path
import re
from setuptools import setup, find_packages

HERE = Path(__file__).parent.resolve()

def read_file(filename: str) -> str:
    p = HERE / filename
    return p.read_text(encoding="utf-8") if p.exists() else ""

def find_version(package: str) -> str:
    init_file = HERE / package / "__init__.py"
    if not init_file.exists():
        return "0.0.0"
    content = init_file.read_text(encoding="utf-8")
    m = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]", content, re.M)
    return m.group(1) if m else "0.0.0"

PACKAGE_NAME = "package_name"
VERSION = find_version(PACKAGE_NAME)
LONG_DESCRIPTION = read_file("README.md")

setup(
    name="names",
    version=VERSION,
    description="description",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown" if (HERE / "README.md").exists() else "text/plain",
    author="",
    license="MIT",
    packages=find_packages(exclude=("tests", "docs")),
    include_package_data=True,
    install_requires=[
        
    ],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)