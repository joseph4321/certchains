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
- COMODO RSA Certification Authority
- thawte Primary Root CA
- Go Daddy Root Certificate Authority - G2
- The Walt Disney Company Issuing CA
- The Walt Disney Company Root CA
