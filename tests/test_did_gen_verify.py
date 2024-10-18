# Cross-Platform Identity Authentication and End-to-End Encrypted Communication Technology Based on DID
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: http://pi-unlimited.com
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import unittest
import json
from agent_connect.utils.did_generate import did_generate, sign_did_document_secp256r1
from agent_connect.utils.did_verify import verify_did_document, extract_public_key
from cryptography.hazmat.primitives.asymmetric import ec
import logging

class TestDIDManagement(unittest.TestCase):

    def test_did_generation_and_verification(self):
        # Generate DID document and keys
        private_key, public_key, did, did_document_json = did_generate("wss://example.com/endpoint")
        did_document = json.loads(did_document_json)

        # Check if the DID document contains the correct DID
        self.assertIn(did, did_document_json)

        # Verify DID document
        result, message = verify_did_document(did_document)
        self.assertTrue(result, msg="DID document verification failed: " + message)

        # Test signature functionality
        signed_did_document = sign_did_document_secp256r1(private_key, did_document)
        self.assertIn('proofValue', signed_did_document['proof'], "Signature not properly added to DID document")

        # Verify signature again
        result, message = verify_did_document(signed_did_document)
        self.assertTrue(result, msg="Re-signed DID document verification failed: " + message)
        logging.info("DID document verification passed")

    def test_public_key_extraction(self):
        # Generate DID document and keys
        private_key, public_key, did, did_document_json = did_generate("wss://example.com/endpoint")
        did_document = json.loads(did_document_json)

        # Extract public key
        extracted_public_key = extract_public_key(did_document, f"{did}#keys-1")
        self.assertIsInstance(extracted_public_key, ec.EllipticCurvePublicKey, "Extracted public key type is incorrect")

        logging.info("Public key extraction successful")


if __name__ == '__main__':
    unittest.main()

