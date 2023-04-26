import socket               # Import socket module

s = socket.socket()         # Create a socket object
host = "192.168.12.1" 
port = 6060               	# Reserve a port for your service.

s.connect((host, port))
s.send(b'Finished')
s.close()