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
# chain is DLX-Disney OFE TST Sep 16 12:00:00 2018 GMT ---- unable to complete chain (DigiCert SHA2 Assured ID CA was not found in trust store)
# chain is disneyauth.altaresources.com ---- thawte SSL CA - G2 ---- thawte Primary Root CA
# chain is twdc.corp.passwordreset ---- The Walt Disney Company Issuing CA ---- The Walt Disney Company Root CA
#
# Summary of found CA's:
#- COMODO RSA Certification Authority Jan 18 23:59:59 2038 GMT
#- thawte Primary Root CA Jul 16 23:59:59 2036 GMT
#- Go Daddy Root Certificate Authority - G2 Dec 31 23:59:59 2037 GMT
#- RapidSSL SHA256 CA - G3 May 20 21:39:32 2022 GMT --- This CA does not have valid leaf certs
#- The Walt Disney Company Issuing CA Sep 15 19:42:04 2027 GMT
#- The Walt Disney Company Root CA Sep  5 13:55:06 2030 GMT


print "-" x 80;
print "\n";
print "This script will extract cert chain and CA information from the API Gateway\n";
print "Note that:\n";
print "- objects that have \"unable to complete chain (<issuer> was not found in trust store)\" means that the issuer of the cert was not found in the group of available certs\n";
print "- objects that have \"Missing from trust store\" means that the issuer was not found in the gateway trust store, but was manually added to missingcerts.csv.  It is unclear if these certs will work in production\n";
print "- objects that have \"This CA does not have valid leaf certs\" means that the CA does not have a valid leaf cert that references it, which could mean no certs reference it, or only expired leaf certs are using it\n";
print "- objects that end in \"-1\", \"-2\", \"-3\", etc. means that the name of the object was previously found.  Both instances will need to be kept in case the cert was renewed and both are being kept in the policy, and/or the cert switched CA's.\n\n";
print "This script will output information in the following format:\n";
print "chain is <client cert> ---- <intermediate cert> ---- <root cert>\n";
print "Summary of found CA's:\n";
print "- <Certificate Authority>\n";
print "-" x 80;
print "\n\n";



# Environment
$env="ext";

# Cert info
@rootcerts = ();
@allca = ();
@missingcerts = ();
%allcerts = {};
%certexpires = {};
%cavalidleaf = {};
$fromtruststore = 0;

# grab the missing intermediate certs
# these intermediate certs were not found in the trust store, but were
# verified to have client certs attached to them that work
# they were manually added to the missingcerts.csv file as base64 pem encoded
$missing_ca_raw = `cat missingcerts.csv`;
@missing_ca_split = split(',',$missing_ca_raw);
foreach $cert (@missing_ca_split){
	$fromtruststore = 0;
	chomp($cert);
	if($cert !~ /BEGIN CERTIFICATE/){next;}
	printCertInfo($cert);
}

# client certs extracted from db
$client_certs_raw = `cat client_cert.csv`;
@client_certs_split = split('\[\]\[\]\[\]',$client_certs_raw);

foreach $cert (@client_certs_split){
	$fromtruststore = 1;
        $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        printCertInfo($cert);
}

# trusted certs extracted from db
$trusted_certs_raw = `cat trusted_cert.csv`;
@trusted_certs_split = split('\[\]\[\]\[\]',$trusted_certs_raw);

foreach $cert (@trusted_certs_split){
	$fromtruststore = 1;
        $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        printCertInfo($cert);
}

# certs found in the policy
@files=`ls /var/www/html/data/certs/*-ext.cer`;

foreach $file (@files){
	$fromtruststore = 1;
        $buf = `cat $file`;
        printCertInfo($buf);
}

# cycle through the allcerts array and build the trust chain to root
# make a note of the intermediate and root certs that are seen
$cert="";
$issuer="";
$chain = "";
$expire = "";
$fromtruststore = 0;
@foundca = ();
@formattedcert = ();
$curDate = `date +%s`;chomp($curDate);
while(($cert,$issuer) = each(%allcerts)){

	# if this is a ca, ignore
	$cafound=0;
	foreach $ca (@allca){
		if($ca eq $cert){$cafound=1;}
	}
	if($cafound == 1){next;}


	# get the cert expiration date and note if it is expired
	# if it is not expired, the issuing ca has at least one cert that is not expired
	$expire = $certexpires{$cert};
	$epoch = `date --date="$expire" +%s`;chomp($epoch);
	$diff = $epoch - $curDate;
	if($diff > 0){$cavalidleaf{$issuer}=1;}

        $chain = $cert . " " . $certexpires{$cert} . " ---- ";


        # while the the issuer of the cert exists in the array
	$rootcertfound=0;
	$usesmissingca=0;
        while(exists $allcerts{"$issuer"}){

		# if client cert valid, note the issuer has a valid leaf cert
		if($diff > 0){$cavalidleaf{$issuer}=1;}


                # check if a ca is found and save it
		# if already exists, ignore
                $found=0;
                for($i=0;$i<@foundca;$i++){
                        if($foundca[$i] eq $issuer){$found=1;}
                }
                if($found == 0){push(@foundca,$issuer);}


		# check if this is a missing cert that was manually added
		$found=0;
		for($i=0;$i<@missingcerts;$i++){
			if($issuer eq $missingcerts[$i]){$found=1;}
		}
		if($found == 1){ $chain .= "(Missing from trust store) ";}


                # check if the issuer is a root cert
                # if it is, break out of the loop
                $rootcertfound=0;
                foreach $c (@rootcerts){
                        if($c eq $issuer){
                        	$rootcertfound = 1;
                        }
                }
                if($rootcertfound == 1){
                        $chain .= $issuer . " " . $certexpires{$issuer};
                        last;
                }


                # still not at a root cert, note the issuer, and continue
                $chain .= $issuer . " " . $certexpires{$issuer} . " ---- ";
                $issuer = $allcerts{"$issuer"};

        }
	
	# if unable to get to the root cert, make a note in the output
	if($rootcertfound == 0){ $chain .= "unable to complete chain ($issuer was not found in trust store)";}

        print "chain is $chain\n";
}

# print out the found ca's
print "\n\n\n";
print "Summary of found CA's:\n";
foreach $ca (@foundca){

	# note if the CA has valid leaf certs
	$valid = "";
	if($cavalidleaf{$ca} == 0){$valid = " --- This CA does not have valid leaf certs";}

	print "- $ca " . $certexpires{$ca} . $valid . "\n";
}










# expects a pem formated cert
sub printCertInfo{
	$cert = shift(@_);

	# format the cert and extract data with openssl
        @r = `echo "$cert" | openssl x509 -noout -text`;

	# look for needed information in the formatted output
        $certName="";
        $issuer="";
	$issuerbuf="";
        $certbuf="";
        $subjectbuf="";
	$exipire="";
        foreach $line (@r){
                $certbuf.=$line;
                if($line =~ /Issuer\: .*CN\=(.*)\n/){$issuer=$1;chomp($issuer);}
                if($line =~ /Issuer\: (.*)/){$issuerbuf=$1;chomp($issuerbuf);}
                if($line =~ /Subject\: .*CN\=(.*)/){$certName = $1;chomp($certName);}
                if($line =~ /Subject\: (.*)/){$subjectbuf = $1;chomp($subjectbuf);}
		if($line =~ /Not After : (.*)/){$expire = $1;chomp($expire);}
        }

	# use the full subject if the nicer cn is not available
        if ($certName eq ""){$certName=$subjectbuf;}

	# use the full issuer if the nicer cn is not available
	if ($issuer eq ""){$issuer=$issuerbuf;}

	# if the certname equals the issuer, this is a root cert
        if($certName eq $issuer){push(@rootcerts,$certName);}

	# record all of the ca's, not just root
	$foundca=0;
	foreach $ca (@allca){
		if($issuer eq $ca){$foundca=1;}
	}
	if($foundca == 0){push(@allca,$issuer);}

	# check for duplicate entries in allcerts.  If duplicate found, add "-$i",
	# where $i increases everytime a collision occurs;  Needed if a customer
	# moves/renews their cert to another CA, but both certs still exist in the policy
        $i=1;
        while(exists $allcerts{"$certName"}){
                if($i > 1){chop($certName);chop($certName);}
                $certName .= "-$i";
                $i++;
        }

	# add the cert to the found certs
        $allcerts{"$certName"} = $issuer;

	# add the cert expiration date
	$certexpires{"$certName"} = $expire;

	# add the cert for valid leaf checks
	$cavalidleaf{"$certName"} = 0;

	# note if this cert is not from the trust store
	if($fromtruststore == 0){push(@missingcerts,$certName);}
}

