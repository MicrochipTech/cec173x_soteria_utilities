

set ecdsa_key_filename=ec384_32.pem
set ecdsa_key_filename_pass=ec384_32
set csr_file=%ecdsa_key_filename_pass%_csr.pem
set crt_file=%ecdsa_key_filename_pass%_crt.pem


openssl.exe ecparam -name secp384r1 -genkey | openssl.exe ec -out %ecdsa_key_filename% -passout pass:%ecdsa_key_filename_pass% -aes-256-cbc

openssl.exe req -new -key %ecdsa_key_filename% -out %csr_file% -passin pass:%ecdsa_key_filename_pass% -subj /C=US/ST=NYC/L=Hauppauge/O=MCHP/OU=CPG-FW/CN=CEC1712

openssl.exe x509 -req -days 3650 -in %csr_file% -signkey %ecdsa_key_filename% -out %crt_file% -passin pass:%ecdsa_key_filename_pass%