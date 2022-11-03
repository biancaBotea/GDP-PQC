# GDP-PQC

We are going to modify existing benchmarking software to easily analyse and compare the security,
implementation costs and energy consumption of PQC methods.

## Build

Compile Benchmark.c using:

    gcc Benchmark.c client-pq-tls13.c -lwolfssl -o Benchmark

Then run Benchmark executable as normal.