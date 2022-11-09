path = "../Results/"
ext = ".txt"
side = ["client-","server-"]
benchmark = ["latency-", "heap-usage-"]

algorithm = ["dilithium","falcon","ecc"]
dilitiumconfigs = ["l2","l3","l5"]
falconconfigs = ["l1","l5"]

class latency_test:
    def __init__(self, side, cipher, group, totalBytes, numConns, Rx_ms, Tx_ms, Rx_MBps, Tx_MBps, connTotal_ms, connAve_ms):
        self.side = side
        self.cipher = cipher
        self.group = group
        self.totalBytes = int(totalBytes)
        self.numConns = int(numConns)
        self.Rx_ms = float(Rx_ms)
        self.Tx_ms = float(Tx_ms)
        self.Rx_MBps = float(Rx_MBps)
        self.Tx_MBps = float(Tx_MBps)
        self.connTotal_ms = float(connTotal_ms)
        self.connAve_ms = float(connAve_ms)

    def __repr__(self):
        pass

class heap_usage_test:
    def __init__(self, sig, kem, totalAllocs, totalDeallocs, totalBytes, peakBytes, currentBytes):
        self.sig = sig
        self.kem = kem
        self.totalAllocs = int(totalAllocs)
        self.totalDeallocs = int(totalDeallocs)
        self.totalBytes = int(totalBytes)
        self.peakBytes = int(peakBytes)
        self.currentBytes = int(peakBytes)

def parseLatencyFile(filepath):
    f = open(filepath, "r")
    l = 0
    for line in f:
        l += 1
        if l % 2 == 1 and l >=3:
            latencyParams = list()
            writing = True
            last_c = ""
            param = ""
            for c in line:
                if writing == False and last_c == " " and c != " ":
                    writing = True

                if c == " ":
                    writing = False
                    if param != "":
                        latencyParams.append(param)
                        param = ""

                elif writing == True:
                    # append character to parameter
                    param = param + c
                
                last_c = c
            return latency_test(latencyParams[0],latencyParams[1],latencyParams[2],\
                latencyParams[3],latencyParams[4],latencyParams[5],latencyParams[6],\
                latencyParams[7],latencyParams[8],latencyParams[9],)


def main():
    parseLatencyFile("../Results/server-latency-dilithium-l2.txt")

main()