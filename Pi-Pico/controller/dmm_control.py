import sys, getopt
import easy_scpi as scpi


def main(argv):
    logging = False
    filename = ""
    opts, args = getopt.getopt(argv,"l:f:",["log=","filename="])
    for opt, arg in opts:
        if opt in ("-l", "--log"):
            if arg == "on":
                logging = True
            elif arg == "off":
                logging = False
            else:
                print("Invalid logging value")
                exit()
        elif opt in ("-f", "--filename"):
            filename = arg

    inst = scpi.Instrument("ASRL33::INSTR")
    inst.connect()

    if filename != "":
        inst.write("DATA:LOG:FNAM \"" + filename + "\",EXT")

    if logging:
        inst.write("DATA:LOG:MODE UNL")
        inst.write("DATA:LOG ON")
    else:
        inst.write("DATA:LOG OFF") 


if __name__ == "__main__":
   main(sys.argv[1:])
