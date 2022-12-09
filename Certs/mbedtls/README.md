<!-- How to generate post-quantum certs with MbedTLS -->
# Generating Client and Server Certificates

To generate certs that can be used with the version of MbedTLS used in this project the `gen_key` and `cert_write` applications must be used. 

## Generating a Self-Signed Certificate

In our case we don't need a certificate authority (CA) to give us a certificate for our server because we're not aiming to interact with the wider internet. The alternative is to generate our own root certificate in place of the certificate authorities certificate. To do this we generate a key pair and then use the private key to sign a certificate with the CA property set to true. 

### Generating a Public-Private Key Pair

To generate a key pair using the applications bundled with MbedTLS `gen_key` is required. This is located at `./programs/pkey`. The paramaters available set the key algorithm, length and output file name. Since we're using implementations of algorithms with a fixed length key we don't need to specify length. Also, the version of MbedTLS used at the time of writing only has one post-quantum signature scheme, SPHINCS+, so algorithm is specified as `pq`. The full command is:

    ```sh
    ./programs/pkey/gen_key type=pq filename=sphincs_ca_root_key.pem
    ```

This assumes you're running everything from the MbedTLS root directory. This way all the files produced will be in the same, easy to find folder. 

### Generating the Root Certificate

To generate a root certificate using the private key generated above the `cert_write` application is required. This is located at `./programs/x509`. The parameters determine certificate validity dates and times, issuer information, subject information and more. The command used here was:

    ```sh
    /programs/x509/cert_write selfsign=1 issuer_key=sphincs_ca_root_key.pem issuer_name=CN=Root\ Certificate,O=UoS,C=UK not_before=20220101000000 not_after=20270101000000 is_ca=1 max_pathlen=0 output_file=sphincs_ca_root_cert.pem
    ```

In the case of the root certificate the issuer and subject are the same so subject information can be omitted. Also, the CA flag must be set to true along with the selfsign variable and the `max_pathlen=0` specifies whether the certificate can be used to generate intermediate CA certificates.

## Generating an Entity Certificate

With a self-signed certificate acting as a substitute for a trusted root certificate from a CA we can now generate a certificate for our server. To do this we need another key pair which is in theory generated on the server and only the public part is used. 

### Generating another Public-Private Key Pair

This follows the same method as before but we rename the output file:

    ```sh
    ./programs/pkey/gen_key type=pq filename=sphincs_entity_key.pem
    ```

### Generating the Entity Certificate

The root certificate must be able to verify the entity certificate therefore the root key is needed at this stage as well as the server key. The command to generate the entity certificate is as follows:

    ```sh
    ./programs/x509/cert_write issuer_key=sphincs_ca_root_key.pem subject_key=sphincs_entity_key.pem issuer_name=CN=Root\ Certificate,O=UoS,C=UK subject_name=CN=Entity\ Certificate,O=UoS,C=uk not_before=20220101000000 not_after=20270101000000 output_file=sphincs_entity_cert.pem
    ```

## Transferring the Certificates to MbedTLS

As this project uses char buffers to store certificates we cannot just provide MbedTLS with the pem files in order to use them. They must be converted to a char and saved in the application code. The easiest method to convert a .pem file into a char buffer is to use the following command and then copy the output from the terminal into the desired location.

    ```sh
    cat sphincs_entity_cert.pem | while read line; do echo -e "\""${line}$"\\\r\\\n\"\t\\"; done
    ```

Note: This produces an output finishing with a slash that needs to be removed in order for the char to adhere the correct syntax.