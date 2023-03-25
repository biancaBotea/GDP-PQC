import socket               # Import socket module
import sys, getopt

      
host = "192.168.12.1" 
port = 4444                	# Reserve a port for your service.

def main(argv):
    s = socket.socket()     # Create a socket object
    command = ""
    opts, args = getopt.getopt(argv,"c:",["command="])
    for opt, arg in opts:
        if opt in ("-c", "--command"):
            command = arg
    
    s.connect((host, port))
    s.send(str.encode(command))
    s.close()

if __name__ == "__main__":
   main(sys.argv[1:])