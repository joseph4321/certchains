# Cert Chains
 
A tool for extracing cert chain and CA information from the API Gateway.  
Expects client_cert.csv and trusted_cert.csv to exist in the same directory.  
Data extracted from the db using:  
select cert from client_cert into outfile '/tmp/client_cert.csv' fields terminated by '||||' lines terminated by '[][][]';  
select cert_base64 from trusted_cert into outfile '/tmp/trusted_cert.csv' fields terminated by '||||' lines terminated by '[][][]';  
Will also extract certs from missingcerts.csv that can be manually added to the trust store  

Example Output:  
chain is polaris-pivs.karmalab.net ---- Expedia Internal 1C ---- Expedia MS Root CA (2048)  
chain is tableiq.com ---- RapidSSL CA ---- GeoTrust Global CA  
chain is DLX-Disney OFE TST Sep 16 12:00:00 2018 GMT ---- unable to complete chain (DigiCert SHA2 Assured ID CA was not found in trust store)  
chain is disneyauth.altaresources.com ---- (Missing from trust store) thawte SSL CA - G2 ---- thawte Primary Root CA  
chain is twdc.corp.passwordreset ---- The Walt Disney Company Issuing CA ---- The Walt Disney Company Root CA  

Summary of found CA's:  
- COMODO RSA Certification Authority Jan 18 23:59:59 2038 GMT  
- thawte Primary Root CA Jul 16 23:59:59 2036 GMT  
- Go Daddy Root Certificate Authority - G2 Dec 31 23:59:59 2037 GMT  
- RapidSSL SHA256 CA - G3 May 20 21:39:32 2022 GMT --- This CA does not have valid leaf certs  
- The Walt Disney Company Issuing CA Sep 15 19:42:04 2027 GMT  
- The Walt Disney Company Root CA Sep  5 13:55:06 2030 GMT  
