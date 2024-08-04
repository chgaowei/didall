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

# Import necessary modules for unit testing, system operations, asynchronous programming, and mocking

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
sys.path.append(current_directory)
sys.path.append(current_directory + "/../")
sys.path.append(current_directory + "/../../")
# 创建测试加载器
loader = unittest.TestLoader()
suite = unittest.TestSuite()

import logging

# 配置日志格式
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)

# 加载一个目录下的所有测试模块
suite.addTests(loader.discover(start_dir=current_directory, pattern='test_short_term_key.py'))

# 运行测试
runner = unittest.TextTestRunner()
runner.run(suite)
