# Adjustment for Dilithium Certificate Generation
This only applies to dilithium certificates.\
Follow the README but add the following flag before the *output_file* when generating the *root* and *entity* certificates:
>md=SHAKE256
## Example
./programs/x509/cert_write selfsign=1 issuer_key=dilithium_ca_root_key.pem issuer_name=CN=Root\ Certificate,O=UoS,C=UK not_before=20220101000000 not_after=20270101000000 is_ca=1 max_pathlen=0 md=SHAKE256 output_file=dilithium_ca_root_cert.pem
