# Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: http://pi-unlimited.com
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

from setuptools import setup, find_packages

setup(
    name="ai-agent-protocol",
    version="0.1.5",
    packages=find_packages(),
    install_requires=[
        'ecdsa>=0.19.0', 
        'cryptography>=42.0.8', 
        'asn1crypto>=1.5.1', 
        'base58>=2.1.1', 
        'aiohttp>=3.9.5', 
        'requests>=2.32.3', 
        'websockets>=12.0'
    ],
    author="GaoWei Chang",
    author_email="chgaowei@gmail.com",
    description="An SDK for enabling identity authentication and secure encrypted communication between AI agents.",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url="https://github.com/chgaowei/ai-agent-protocol",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
