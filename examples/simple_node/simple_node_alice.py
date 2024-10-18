import asyncio
import json
import os
import logging

from agent_connect.simple_node import SimpleNode
from agent_connect.utils.log_base import set_log_color_level


def generate_did_info(alice_node: SimpleNode):
    # Check if alice.json exists
    if os.path.exists("alice.json"):
        print("Loading existing Alice DID information")
        with open("alice.json", "r") as f:
            alice_info = json.load(f)
        alice_node.set_did_info(alice_info["private_key_pem"], alice_info["did"], alice_info["did_document_json"])
    else:
        print("Generating new Alice DID information")
        private_key_pem, did, did_document_json = alice_node.generate_did_document()
        alice_node.set_did_info(private_key_pem, did, did_document_json)
        
        # Save Alice's DID information
        with open("alice.json", "w") as f:
            json.dump({
                "private_key_pem": private_key_pem,
                "did": did,
                "did_document_json": did_document_json
            }, f)

async def main():
    alice_node = SimpleNode("localhost", "8000", "ws://localhost:8000/ws")
    generate_did_info(alice_node)

    print(f"Alice's DID: {alice_node.did}")

    # Start the node
    alice_node.run()
    
    try:
        while True:
            # Receive message
            sender_did, message = await alice_node.recv_message()
            print(f"Received message from {sender_did}: {message}")
            
            # Send reply
            reply = f"Hello {sender_did}, I'm Alice!"
            success = await alice_node.send_message(reply, sender_did)
            if success:
                print(f"Successfully replied to {sender_did}")
            else:
                print(f"Failed to reply to {sender_did}")
    except asyncio.CancelledError:
        print("Alice node is shutting down...")
    finally:
        await alice_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())
