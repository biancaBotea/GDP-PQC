path = "../Results/"
ext = ".txt"
side = ["client-","server-"]
benchmark = ["latency-", "heap-usage-"]

algorithm = ["dilithium","falcon","ecc"]
dilitiumconfigs = ["l2","l3","l5"]
falconconfigs = ["l1","l5"]

class latency_test:
    def __init__(self, algorithm, algo_config, side, cipher, group, totalBytes, numConns, Rx_ms, Tx_ms, Rx_MBps, Tx_MBps, connTotal_ms, connAve_ms):
        self.algorithm = algorithm
        self.algo_config = algo_config
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
    l = 1
    for line in f:
        if l % 2 == 0 and l >=3:
            rawParams = list()
            latencyParams = list()
            writing = True
            last_c = ""
            rawParamsNum = 0
            for c in line:
                if c != " " and writing == True:
                    latencyParams[rawParamsNum]    
                last_c = c
            l += 1

def main():
    parseLatencyFile("../results/server-latency-dilithium-l2.txt")

main()