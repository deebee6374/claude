from setuptools import setup, find_packages

setup(
    name="emailharvest",
    version="1.0.0",
    description="OSINT email harvesting toolkit for authorized security research",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "dnspython>=2.4.0",
        "python-whois>=0.8.0",
        "tldextract>=5.1.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "chardet>=5.2.0",
        "urllib3>=2.1.0",
    ],
    extras_require={
        "docs": [
            "PyMuPDF>=1.23.0",
            "python-docx>=1.1.0",
            "openpyxl>=3.1.0",
            "pdfminer.six>=20221105",
            "python-pptx>=0.6.23",
        ],
    },
    entry_points={
        "console_scripts": [
            "emailharvest=emailharvest.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
)
