import socket               # Import socket module
import time
import sys
import getopt
import easy_scpi as scpi


def main(argv):
    s = socket.socket()         # Create a socket object
    host = "192.168.12.1"          # Get local machine name
    port = 4444               	# Reserve a port for your service.

    no_tries = 0
    test_count = 0

    inst = scpi.Instrument("ASRL33::INSTR")
    inst.connect()

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

    while True:
        s.listen()                  # Now wait for client connection.
        print("waiting for test to finish")
        c, addr = s.accept()       # Establish connection with client.
        msg = c.recv(1024)
        if (msg == b'Start'):
            test_count += 1
            print("Initiating Data Logging")
            inst.write("DATA:LOG:FNAM \"" + str(test_count) + "\",EXT")
            inst.write("DATA:LOG:MODE UNL")
            inst.write("DATA:LOG ON")
            c.close()
        elif (msg == b'Stop'):
            print("Terminating Data Logging")
            inst.write("DATA:LOG OFF") 
            c.close()


if __name__ == "__main__":
   main(sys.argv[1:])
