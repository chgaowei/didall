import pkg_resources

# 要查找版本的包列表
packages = [
    "ecdsa",
    "cryptography",
    "asn1crypto",
    "base58",
    "pymysql",
    "aiohttp",
    "requests",
    "websockets"
]

# 获取包的版本
def get_package_version(package_name):
    try:
        return pkg_resources.get_distribution(package_name).version
    except pkg_resources.DistributionNotFound:
        return None

# 生成 install_requires 列表
install_requires = []
for package in packages:
    version = get_package_version(package)
    if version:
        install_requires.append(f"{package}=={version}")

print(install_requires)

