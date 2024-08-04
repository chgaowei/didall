# Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: http://pi-unlimited.com
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import unittest
import sys
import os
import asyncio
from unittest.mock import patch, AsyncMock

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
sys.path.append(current_directory)
sys.path.append(current_directory + "/../")
sys.path.append(current_directory + "/../../")
# Create test loader
loader = unittest.TestLoader()
suite = unittest.TestSuite()

import logging

# Configure logging format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)

# Load all test modules in a directory
suite.addTests(loader.discover(start_dir=current_directory, pattern='test_*.py'))

# Run tests
runner = unittest.TextTestRunner()
runner.run(suite)
