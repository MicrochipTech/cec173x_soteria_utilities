
REM curvesTP=prime256v1


SET curvesTP=%1
SET PrivKeyFile=%2
SET PrivKeyPassword=%3
SET subjopt=/C=US/ST=NYC/L=Hauppauge/O=MCHP/OU=CPG-FW/CN=GLACIER
openssl ecparam -name %curvesTP% -genkey | openssl ec -out %PrivKeyFile%.pem -passout pass:%PrivKeyPassword% -aes-256-cbc
openssl req -new -key %PrivKeyFile%.pem -out %PrivKeyFile%_csr.pem -passin pass:%PrivKeyPassword% -subj %subjopt%
openssl x509 -req -days 3650 -in %PrivKeyFile%_csr.pem -signkey %PrivKeyFile%.pem -out %PrivKeyFile%_crt.pem -passin pass:%PrivKeyPassword%
        
openssl x509 -in %PrivKeyFile%_crt.pem -text -noout > %PrivKeyFile%_dump.txt
        
openssl ec -in %PrivKeyFile%.pem -text -passin pass:%PrivKeyPassword%  > %PrivKeyFile%_pub_pvt_dump.txt
