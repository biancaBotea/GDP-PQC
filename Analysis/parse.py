path = "../Results/"
ext = ".txt"
side = ["client","server"]
benchmark = ["latency", "heap-usage"]

algorithm = ["dilithium","falcon","ecc"]
dilitiumconfigs = ["l2","l3","l5"]
falconconfigs = ["l1","l5"]
eccconfigs = [""]

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

class latency_batch:
    def __init__(self, side, algorithm, config):
        self.side = side
        self.algorithm = algorithm
        self.config = config
        if config != "":
            self.filepath = path + side + "-latency-" + algorithm + "-" + config + ext
        else:
            self.filepath = path + side + "-latency-" + algorithm + ext
        self.latencyBatch = self.parseLatencyFile(self.filepath)
        
    def parseLatencyFile(self,filepath):
        f = open(filepath, "r")
        l = 0
        batch = list()
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
                latencyParams.append(param)
                param = ""
                batch.append(latency_test(latencyParams[0],latencyParams[1],latencyParams[2],\
                    latencyParams[3],latencyParams[4],latencyParams[5],latencyParams[6],\
                    latencyParams[7],latencyParams[8],latencyParams[9],latencyParams[10]))
        return batch
     

class heap_usage_test:
    def __init__(self, sig, kem, totalAllocs, totalDeallocs, totalBytes, peakBytes, currentBytes):
        self.sig = sig
        self.kem = kem
        self.totalAllocs = int(totalAllocs)
        self.totalDeallocs = int(totalDeallocs)
        self.totalBytes = int(totalBytes)
        self.peakBytes = int(peakBytes)
        self.currentBytes = int(currentBytes)

class heap_usage_batch:
    def __init__(self, side):
        self.side = side
        self.filepath = path + side + "-heap-usage" + ext
        self.heapUsageBatch = self.parseHeapUsageFile(self.filepath)
    
    def parseHeapUsageFile(self, filepath):
        f = open(filepath, "r")
        l = 0
        batch = list()
        params = list()
        for line in f:
            # interate through and get sig and kems
            if line[0] == "D":
                params.append([])
                for c in range(4,len(line)):
                    if line[c] == " ":
                        params[len(params)-1].append()
                        break
            pass

        for line in f:
            # iterate through and get allocs, deallocs, total bytes, peak bytes 
            pass

def runLatency():
    latency_tests = list()
    for s in side:
        for a in algorithm:
            if a == "dilithium":
                for c in dilitiumconfigs:
                    latency_tests.append(latency_batch(s,a,c))
            elif a == "falcon":
                for c in falconconfigs:
                    latency_tests.append(latency_batch(s,a,c))
            elif a == "ecc":
                c = ""
                latency_tests.append(latency_batch(s,a,c))

runLatency()