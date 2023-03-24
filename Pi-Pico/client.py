import socket               # Import socket module

s = socket.socket()         # Create a socket object
host = "127.0.0.1" # Get local machine name
port = 12345                # Reserve a port for your service.

s.connect((host, port))
s.send(b'Finished')
s.close()