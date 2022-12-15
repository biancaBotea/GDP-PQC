# Pico Benchmarking

## To Do List
- [ ] Modify MbedTLS within the Pico-SDK
- [ ] Develop proof of concepts for latency and heap usage
- [ ] Integrate clock cycle code into client script
- [ ] Generate new client executable(s)
- [ ] Write bash script to automate flashing pico and store output
    - [ ] Establish method of capturing uart stdout to file

## Adding our version of MbedTLS to the Pico-SDK
We need to replace mbedtls-2.28 with mbedtls-2.16-pqc (which we've done before and we know works) and then change a few extra files that to bring it to our current state of development. 

To swap mbedtls-2.28 with mbedtls-2.16-pqc you need to remove the old submodule that's part of the sdk git repo and add a the new version. Don't forget to switch to the pqc branch of the new version once its been added. The pqc mbedtls version we're using is https://github.com/kbuersti/mbedtls.

The final changes are:

- Fixing the compilation errors that come with the  library
    - ssl_server.c - Line 67: 'mbedtls\timing.h' -> 'mbedtls/timing.h'
    - benchmark.c - Line 1055: Remove last 2 params and add new close bracket
- Updating `spx_params.h` to include the round 3 sphincs parameters
- Updating `config.h` to allow heap usage benchmarking via mbedtls

`spx_params.c` and `config.h` can be copied from the Pi-3 benchmarking setup. `spx_params.h` can be found in `/include/pq/` and `config.h` can be found in `/include/mbedtls/`.

## Proof of Concepts
Currently, all benchmarking provided by mbedtls is untested on the pico. Methods for measuring latency and heap usage should transfer easily from the Pi-3 to the Pico but this still needs to be confirmed. This can be done by taking the methods used in benchmark.c and any of our own Pi-3 code that measure latency or heap usage and applying them to the client script for the Pico. It should be noted the Pico has a hardware RTC that should be used for measuring latency.

## Clock Cycle Code Integration
As an alternative to measuring power on the Pico we are going to measure clock cycles. This is acceptable because clock cycles are representative of the power consumed by a device with no operating system e.g. the Pico. Integrating our pre-existing code for clock cycle benchmarking into the pico client script consists of including the necessary prerequisites and replacing the handshake latency benchmarking with the approapriate clock cycle measuring alternatives. Latency and clock cycle measurements should be like for like swaps.

## Generating Client Executable(s)
It's currently unclear whether the pico can support a fully functional client benchmarking script like the Pi. Because only one cert is used at once and unused certs are stored in flash we may have space to store all the certs and only load one at a time. This is speculation though.

If the above doesn't work we will need to build a new executable client for each digital certificate scheme. We don't need a new executable for every ciphersuite because we can change the ciphersuite used for testing on the server side (and hence the KEM) as long as the client has the correct certificate for the intended DS. We can still mimic the Pi-3 benchmarking scripts in terms of looping the client and collecting results though.

The certificates to use have been generated and saved in the correct format already. Use them by including `new_certs.h` in the client script.

It should be noted, the best case scenario is not having to modify the configuration of mbedtls (config.h) between generating these executables. The current setup allows for this because the server is used to change the ciphersuite being tested and the client just supports them all. We may not have this luxury once dilithium is integrated as we may need to disable sphincs to enable dilithium but this remains speculation.

## Bash Scripting for Automation
To enable automated testing that involves multiple executables we will need to develop a bash script which flashes the pico with the executables generated in the previous step. The server should be compatable no matter the length of time between testing the next ciphersuite. 

One area of uncertainty is collecting the results printed to the uart output of the Pico. There may be functionality in minicom to write the output to a file but this needs to be tested.