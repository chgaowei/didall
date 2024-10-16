# Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID

**Author**: Chang Gaowei  
**Email**: chgaowei@gmail.com  
**Website**: [pi-unlimited.com](http://pi-unlimited.com)  
**中文版本**: [中文版本readme](https://github.com/chgaowei/didall/blob/main/README.cn.md)  

## Abstract

We are dedicated to providing communication capabilities for AI Agents, connecting all Agents into a collaborative network.
This project is an open-source SDK implementation based on Decentralized Identifier (DID) and end-to-end encrypted communication technology. For technical details, please refer to the [Technical White Paper: A Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID](https://egp0uc2jnx.feishu.cn/wiki/WMLswhdEUiXzB1kMk54cfFcan2f?from=from_copylink).
With the didall open-source project, any intelligent agent can generate its own DID, locate others based on their DIDs, perform identity authentication, and engage in secure end-to-end encrypted communication.

## Features

- **Cross-platform identity authentication**: Achieve identity interoperability across different platforms through DID.
- **End-to-end encrypted communication**: Use ECDHE for ephemeral key exchange to ensure the security of communication.
- **Efficient and secure**: Simplifies the identity verification process while ensuring the confidentiality and integrity of data.

### Installation

The latest version has been removed from PyPI, so you can install it directly:

```bash
pip install didall
```

### Usage

After installing the didall library, you can run our demo to experience the powerful features of didall. We currently offer two modes: hosted mode and single node mode.

#### Hosted Mode
In hosted mode, we provide a DID server where all DID information is registered, and communication is conducted through the DID server.

You can run the sample code in the examples directory to first generate Alice and Bob's DID files, save Alice's DID file to the DID server, and then Bob can connect to Alice's DID to establish end-to-end encrypted communication.

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

#### Single Node Mode
In single node mode, you don't need any third-party services to complete DID-based identity verification and encrypted communication.

You can run the simple_node code in the examples directory, first start Alice's node, and then start Bob's node to complete identity verification and encrypted communication.

1. Start Alice's node:
```bash
python simple_node_alice.py
```

2. Start Bob's node:
```bash
python simple_node_bob.py
```

## Contributing

Contributions to this project are welcome. Please read the contribution guidelines before submitting a pull request.

## License
    
This project is open-sourced under the MIT License. For more details, please refer to the LICENSE file.

## Packaging and Uploading (update the version number in setup.py first)

```bash
python setup.py sdist bdist_wheel 
twine upload dist/*        
```
