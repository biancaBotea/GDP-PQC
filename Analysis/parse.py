"""
Configurations for parsing files used by runLatency() and runHeapUsage()
"""

path = "../Results/"
ext = ".txt"
side = ["client","server"]
benchmark = ["latency", "heap-usage"]

algorithm = ["dilithium","falcon","ecc"]
dilitiumconfigs = ["l2","l3","l5"]
falconconfigs = ["l1","l5"]
eccconfigs = [""]


class latency_test:
    """
    ### Summary
    class structure for a single latency test
    - __init__()
        - initialise test properties
    """
    def __init__(self, side, cipher, group, totalBytes, numConns, Rx_ms, Tx_ms, Rx_MBps, Tx_MBps, connTotal_ms, connAve_ms):
        """ 
        ### Summary:
        class latency_test __init__()
        ### Parameters:
        - side {string}: client/server side
        - cipher {string}: cipher description
        - group {string}: cipher group
        - totalBytes {integer}: total Bytes
        - numConns {integer}: number of connections
        - Rx_ms {float}: Receive Time (ms)
        - Tx_ms {float}: Transmit Time (ms)
        - Rx_MBps {float}: Receive Rate (MB/s)
        - Tx_MBps {float}:  Transmit Rate (MB/s)
        - connTotal_ms {float}: Total Connection Time
        - connAve_ms {float}: Mean Connection Time
        ### Returns:
        - None
        """
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
    """
    ### Summary
    class structure for batch of latency tests
    - __init__()
        - initialises batch properties and calls parseLatencyFile()
    - parseLatencyFile() 
        - parses a single latency batch file from batch properties
    """
    def __init__(self, side, algorithm, config):
        """
        ### Summary
        - Initialises batch properties and parses latency tests from batch filepath
        ### Parameters:
        - side {string}: Client/Server side
        - algorithm {string}: TLS 1.3 Algorithm
        - config {string}: Algorithm Config
        ### Returns:
        - None
        """
        self.side = side
        self.algorithm = algorithm
        self.config = config
        if config != "":
            self.filepath = path + side + "-latency-" + algorithm + "-" + config + ext
        else:
            self.filepath = path + side + "-latency-" + algorithm + ext
        self.latencyBatch = self.parseLatencyFile(self.filepath)
        
    def parseLatencyFile(self,filepath):
        """
        ### Summary
        - Parse latency test file and store parameters in latency test class structure
        - Initialise latency batch list and store latency tests
        ### Parameters:
        - filepath {string}: latency batch filepath
        ### Returns:
        - list({latency_batch}) 
        """
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
                        param = param + c
                    
                    last_c = c
                latencyParams.append(param)
                param = ""
                batch.append(latency_test(latencyParams[0],latencyParams[1],latencyParams[2],\
                    latencyParams[3],latencyParams[4],latencyParams[5],latencyParams[6],\
                    latencyParams[7],latencyParams[8],latencyParams[9],latencyParams[10]))
        return batch
     

class heap_usage_test:
    """
    ### Summary:
    Class structure for single heap usage test
    - __init__
        - initialises single heap usage test
    """
    def __init__(self, sig, kem, totalAllocs, totalDeallocs, totalBytes, peakBytes):
        """
        ### Summary:
        class heap_usage_test __init__()
        ### Parameters:
        - sig {string}: Signature Method
        - kem {string}: KEM Method
        - totalAllocs: total heap Allocations
        - totalDeallocs: total heap Deallocations (should == totalAllocs)
        - totalBytes: total heap Bytes
        - peakBytes: peak heap Bytes
        ### Returns:
        - None 
        """
        self.sig = sig
        self.kem = kem
        self.totalAllocs = int(totalAllocs)
        self.totalDeallocs = int(totalDeallocs)
        self.totalBytes = int(totalBytes)
        self.peakBytes = int(peakBytes)

class heap_usage_batch:
    """
    ### Summary:
    class structure for batch of heap usage tests
    - __init__()
        - initiailises batch properties and calls parseHeapUsageFile()
    - parseHeapUsageFile()
        - parses a single heap usage batch file from batch properties
    """
    def __init__(self, side):
        """
        ### Summary
        - Initialises batch properties and parses heap usage tests from batch filepath
        ### Parameters
        - side {string}: Client/Server side
        ### Returns:
        - None
        """
        self.side = side
        self.filepath = path + side + "-heap-usage" + ext
        self.heapUsageBatch = self.parseHeapUsageFile(self.filepath)
    
    def parseHeapUsageFile(self, filepath):
        """
        ### Summary
        - Parse heap usage test file and store parameters in heap usage test class structure
        - Initialise heap usage batch list and store heap usage tests
        ### Parameters:
        - filepath {string}: heap usage batch filepath
        ### Returns:
        - list({heap_usage_batch})
        """
        f = open(filepath, "r")
        p = 0
        batch = list()
        params = list()
        for line in f:
            # interate through and get sig and kems
            if line[0] == "D":
                params.append([])
                pindex = 0
                Writing = False
                #this can be simplified by starting write from two-char string ": "
                for c in range(0,len(line)):
                    if line[c] == " " and line[c-1] == ":":
                        Writing = True
                        params[p].append("")
                    elif (line[c]==" " and Writing and not line[c-1]==":") or line[c] == "\n":
                        # skip whitespace between : and string by checking if it
                        # doesn't come after a colon to reset
                        Writing = False
                        pindex += 1
                    elif Writing and not line[c]==" ":
                        # do not write gap whitespace
                        params[p][pindex] = params[p][pindex] + line[c]
                p += 1
        f.seek(0)
        p = 0
        for line in f:
            # iterate through and get allocs, deallocs, total bytes, peak bytes
            if "total   Allocs   " in line:
                params[p].append("")
                pindex = 2
            elif "total   Deallocs " in line:
                params[p].append("")
                pindex = 3
            elif "total   Bytes    " in line:
                params[p].append("")
                pindex = 4
            elif "peak    Bytes    " in line:
                params[p].append("")
                pindex = 5
            elif "current Bytes    " in line:
                p += 1
                continue

            afterEq = False
            for c in range(0,len(line)):
                if line[c] == "=":
                    afterEq = True
                    # params[p].append("")
                elif line[c] == "\n":
                    break
                elif afterEq and line[c]!=" " and line[c] !="=":
                    params[p][pindex] = params[p][pindex] + line[c]

        for ht in params:
            batch.append(heap_usage_test(ht[0], ht[1],ht[2],\
                ht[3], ht[4], ht[5]))


def runLatency():
    """
    ### Summary
    - Parse full set of latency tests from parse.py configurations
    ### Parameters:
    - None
    ### Returns:
    - list({latency_batch})
    """
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
    return latency_tests

def runHeapUsage():
    """
    ### Summary
    - Parse full set of heap usage tests from parse.py configurations
    ### Parameters:
    - None
    ### Returns:
    - list({heap_usage_batch})
    """
    heap_usage_tests = list()
    for s in side:
        heap_usage_tests.append(heap_usage_batch(s))
    return heap_usage_tests