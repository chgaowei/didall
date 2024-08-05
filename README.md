# Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID

**Author**: Chang Gaowei  
**Email**: chgaowei@gmail.com  
**Website**: [pi-unlimited.com](http://pi-unlimited.com)  
**中文版本**: [中文版本readme](https://github.com/chgaowei/didall/blob/main/README.cn.md)  

## Abstract

This project is an open-source SDK implementation based on Decentralized Identifier (DID) and end-to-end encrypted communication technology. For technical details, refer to the [Technical White Paper: A Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID](https://egp0uc2jnx.feishu.cn/wiki/JyaIwTwngiWi9qkJjjycI4XcnXe?from=from_copylink). With the didall open-source project, any intelligent agent or server can connect to the DID server, register its DID, accept connections from other users, connect to other users, and engage in end-to-end encrypted communication.

## Features

- **Cross-Platform Identity Authentication**: Achieves identity interoperability across different platforms using DID.
- **End-to-End Encrypted Communication**: Uses ECDHE for short-term key agreement to ensure communication security.
- **Efficient and Secure**: Simplifies the identity verification process, ensuring data confidentiality and integrity.

### Installation

The latest version has been removed from PyPI, so install directly:

```bash
pip install didall
```

### Usage

After installing the didall library, you can run the sample code in the examples directory to generate DID files for Alice and Bob, save Alice's DID file to the DID server, and then have Bob connect to Alice's DID for end-to-end encrypted communication.

1. Generate two DID documents, alice.json and bob.json, save them to the specified files, and register them with the DID server:
```bash
python sample_did.py alice.json
python sample_did.py bob.json
```

2. Start Alice's demo:
```bash
python sample_alice.py alice.json
```

3. Start Bob's demo:
```bash
python sample_bob.py bob.json
```

By checking the logs, you can see that Alice and Bob have successfully connected and engaged in end-to-end encrypted communication.

## Contributing

Contributions to this project are welcome. Please read the contribution guidelines before submitting a pull request.

## License
    
This project is open-sourced under the MIT License. For more details, please refer to the LICENSE file.

## Packaging and Uploading (update the version number in setup.py first)

```bash
python setup.py sdist bdist_wheel 
twine upload dist/*        
```