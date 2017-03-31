#!/usr/bin/perl
#
# A tool for extracing cert chain and CA information from the API Gateway
# Expects client_cert.csv and trusted_cert.csv to exist in the same directory
# Data extracted fromt he db using:
# select cert from client_cert into outfile '/tmp/client_cert.csv' fields terminated by '||||' lines terminated by '[][][]';
# select cert_base64 from trusted_cert into outfile '/tmp/trusted_cert.csv' fields terminated by '||||' lines terminated by '[][][]';
# 
# Example Output:
#
# chain is polaris-pivs.karmalab.net ---- Expedia Internal 1C ---- Expedia MS Root CA (2048)
# chain is tableiq.com ---- RapidSSL CA ---- GeoTrust Global CA 
# chain is disneyauth.altaresources.com ---- thawte SSL CA - G2 ---- thawte Primary Root CA
# chain is twdc.corp.passwordreset ---- The Walt Disney Company Issuing CA ---- The Walt Disney Company Root CA
#
# Summary of found CA's:
#- COMODO RSA Certification Authority
#- thawte Primary Root CA
#- Go Daddy Root Certificate Authority - G2
#- The Walt Disney Company Issuing CA
#- The Walt Disney Company Root CA




# Environment
$env="ext";

# Cert info
@rootcerts = ();
%allcerts = {};



# client certs extracted from db
$client_certs_raw = `cat client_cert.csv`;
@client_certs_split = split('\[\]\[\]\[\]',$client_certs_raw);

foreach $cert (@client_certs_split){
        $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        printCertInfo($cert);
}

# trusted certs extracted from db
$trusted_certs_raw = `cat trusted_cert.csv`;
@trusted_certs_split = split('\[\]\[\]\[\]',$trusted_certs_raw);

foreach $cert (@trusted_certs_split){
        $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        printCertInfo($cert);
}

# certs found in the policy
@files=`ls /var/www/html/data/certs/*-ext.cer`;

foreach $file (@files){
        $buf = `cat $file`;
        printCertInfo($buf);
}

# cycle through the allcerts array and build the trust chain to root
# make a note of the intermediate and root certs that are seen
$cert="";
$issuer="";
$chain = "";
@foundca = ();
while(($cert,$issuer) = each(%allcerts)){
        $chain = $cert . " ---- ";

        # while the the issuer of the cert exists in the array
        while(exists $allcerts{$issuer}){

                # check if a ca is found and save it
		# if already exists, ignore
                $found=0;
                for($i=0;$i<@foundca;$i++){
                        if($foundca[$i] eq $issuer){$found=1;}
                }
                if($found == 0){push(@foundca,$issuer);}


                # check if the issuer is a root cert
                # if it is, break out of the loop
                $rootcertfound=0;
                foreach $c (@rootcerts){
                        if($c eq $issuer){
                                $rootcertfound = 1;
                        }
                }
                if($rootcertfound == 1){
                        $chain .= $issuer;
                        last;
                }

                # still not at a root cert, note the issuer, and continue
                $chain .= $issuer . " ---- ";
                $issuer = $allcerts{$issuer};

        }
        print "chain is $chain\n";
}

# print out the found ca's
print "\n\n\n";
print "Summary of found CA's:\n";
foreach $ca (@foundca){print "- $ca\n";}










# expects a pem formated cert
sub printCertInfo{
	$cert = shift(@_);

	# format the cert and extract data with openssl
        @r = `echo "$cert" | openssl x509 -noout -text`;

	# look for needed information in the formatted output
        $certName="";
        $issuer="";
        $certbuf="";
        $subjectbuf="";
        foreach $line (@r){
                $certbuf.=$line;
                if($line =~ /Issuer\: .*CN\=(.*)\n/){$issuer=$1;chomp($issuer);}
                if($line =~ /Subject\: .*CN\=(.*)/){$certName = $1;chomp($certName);}
                if($line =~ /Subject\: (.*)/){$subjectbuf = $1;chomp($subjectbuf);}
        }

	# use the full subject if the nicer cn is not available
        if ($certName eq ""){$certName=$subjectbuf;}

	# if the certname equals the issuer, this is a root cert
        if($certName eq $issuer){push(@rootcerts,$certName);}


	# check for duplicate entries in allcerts.  If duplicate found, add "-$i",
	# where $i increases everytime a collision occurs;  Needed if a customer
	# moves/renews their cert to another CA, but both certs still exist in the policy
        $i=1;
        while(exists $allcerts{$certName}){
                if($i > 1){chop($certName);chop($certName);}
                $certName .= "-$i";
                $i++;
        }

	# add the cert to the found certs
        $allcerts{$certName} = $issuer;
}

