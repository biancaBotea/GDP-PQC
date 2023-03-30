import socket               # Import socket module
import time

s = socket.socket()         # Create a socket object
host = "192.168.12.1"          # Get local machine name
port = 6060              	# Reserve a port for your service.

no_tries = 0

for i in range(0,5):
    try:
        s.bind((host, port))# Bind to the port
        break
    except:
        no_tries += 1
        print("Failed to Bind, Retrying...")
        time.sleep(3 * no_tries)

if no_tries == 5:
    exit(1)

s.listen()                  # Now wait for client connection.

pico_done = False
print("waiting for test to finish")

while not pico_done:
    c, addr = s.accept()     # Establish connection with client.
    msg = c.recv(1024)
    if (msg == b'Finished'):
        print("Pi -> Ubuntu: Pico Finished")
        c.close()
        s.shutdown(socket.SHUT_RDWR)
        s.close()
        pico_done = True