# Cert Chains
 
A tool for extracing cert chain and CA information from the API Gateway.  
Expects client_cert.csv and trusted_cert.csv to exist in the same directory.  
Data extracted from the db using:  
select cert from client_cert into outfile '/tmp/client_cert.csv' fields terminated by '||||' lines terminated by '[][][]';  
select cert_base64 from trusted_cert into outfile '/tmp/trusted_cert.csv' fields terminated by '||||' lines terminated by '[][][]';  

Example Output:  
chain is polaris-pivs.karmalab.net ---- Expedia Internal 1C ---- Expedia MS Root CA (2048)  
chain is tableiq.com ---- RapidSSL CA ---- GeoTrust Global CA   
chain is disneyauth.altaresources.com ---- thawte SSL CA - G2 ---- thawte Primary Root CA  
chain is twdc.corp.passwordreset ---- The Walt Disney Company Issuing CA ---- The Walt Disney Company Root CA  

Summary of found CA's:  
- COMODO RSA Domain Validation Secure Server CA Feb 11 23:59:59 2029 GMT  
- thawte Primary Root CA Jul 16 23:59:59 2036 GMT  
- Go Daddy Root Certificate Authority - G2 Dec 31 23:59:59 2037 GMT  
- The Walt Disney Company Issuing CA Sep 15 19:42:04 2027 GMT  
- The Walt Disney Company Root CA Sep  5 13:55:06 2030 GMT  
