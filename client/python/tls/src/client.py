import socket
import ssl
import json
from platform import system, machine, version

# Server configuration
HOST = 'localhost'  # Replace with your server's address
PORT = 443  # Replace with your server's TLS port

# Certificate as a string
CERT_STRING = "-----BEGIN CERTIFICATE-----\n" \
              "MIICyTCCAbGgAwIBAgIUUbWL3OkQHLYsfcWa75KHrC53sB4wDQYJKoZIhvcNAQEL" \
              "BQAwDTELMAkGA1UEBhMCVVMwHhcNMjUwMTAzMjMyMjM0WhcNMjYwMTAzMjMyMjM0" \
              "WjANMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB" \
              "AMhvwFXIho24QZE9TQMGn5mJe5HErEH3UsvmtwEuumsQrdd6JHApze8Ntl+2+hL4" \
              "7+Ep1agO5bDqFX1zbtuC9fUBkz42tqnrpbRQ2tyUoPKy4aTRQvvA0YVt4bvnjcA3" \
              "nt+UsiyCv9mWUzsTest//eATHnnh+oFRvadDzVJKgZ45XefId5djAdfV5QIEx6k5" \
              "mezwROddVHKyCwIGTg16dstsa/Ci20Y/a6T3uO45GXI8perT5UUVda1jpldEvYY0" \
              "pZ3gdg8BRJUzUpkBST9xdrc2FejarEiykkq3YKXcN/OUvd2YKJCWjfzh0EC2KMIj" \
              "WC7Aqxu53cgBk/+vEfDsHcsCAwEAAaMhMB8wHQYDVR0OBBYEFGzXt/xizLit1viz" \
              "gV9tQUgo6umaMA0GCSqGSIb3DQEBCwUAA4IBAQAsijmzLd9jdwcXpjY6nuxyYfRo" \
              "BxyqTYXLhlb/EpwlCa6NkcIhIOaKiVTGMpVADViRmCPardEbqUXT374pN3mF8PlS" \
              "yiHxAbOoqM9EExtLDlZ2UbAHJ3etXq1MVR0Lm+5BXZW54M56jx6X9Kbtmul8kT0K" \
              "PqycDwcixTONDicZcOuqr+BfzYQ23yMufec9c7f5pVOtsIZzxLvYnosUw93HsnXS" \
              "FP39+wQHGeYjDuywGvYba+2pWORN81KcGbmkYZGGh+Mxj3DKg9qNvHsYI55WACQ+" \
              "e7l3hDJW49mgBO4eEz6Ee+5Dv8NiM9IJPFk6NujQ2F1tEfwbr/n7PI8lMDJT\n" \
              "-----END CERTIFICATE-----"

# Custom SSL/TLS configuration
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cadata=CERT_STRING)

# Testing
#context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
#context.check_hostname = False
#context.verify_mode = ssl.CERT_NONE

# Specify ciphers compatible with the server
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
    

def send_data(connection, data):
    """Sends data to the server."""
    try:
        json_data = json.dumps(data)
        connection.sendall(json_data.encode('utf-8'))
        print(f"Sent: {json_data}")
    except Exception as e:
        print(f"Error sending data: {e}")

def receive_data(connection):
    """Receives data from the server."""
    try:
        data = connection.recv(4096)  # Adjust buffer size as needed
        if data:
            print(f"Received: {data.decode('utf-8')}")
        return data
    except Exception as e:
        print(f"Error receiving data: {e}")
        return None

def main():
    try:
        # Create a secure TLS connection
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as secure_sock:
                print(f"Connected to {HOST}:{PORT} using TLS")

                # Example data to send
                beacon_data = {'response': {
                    'beacon': True,
                    'version': "1.0",
                    'type': "py",
                    'platform': system(),
                    'arch': machine(),
                    'osver': version(),
                    'hostname': secure_sock.getpeername()
                }}

                # Send data to the server
                send_data(secure_sock, beacon_data)

                # Receive data from the server
                receive_data(secure_sock)

    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    main()
