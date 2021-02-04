#!/bin/bash
#Nuclei just give number of new vulns,so have to check the new urls with nuclei manually
#Does not take screenshots take manually, remember database is in .gdrive/.Database
host=$1
#Change the word list path to use your own wordlist.Word lists must end with wordlist.txt. e.g /path/wordlist.txt
wordlist_dns="/root/tools/reporter/wordlist.txt"
resolvers="/root/tools/reporter/resolvers.txt"

subdomain_enum(){
for sub in $(cat $host);
do
mkdir -p $sub $sub/Subdomains $sub/ReconData $sub/ReconData/subjack $sub/ReconData/paramlist $sub/ReconData/nuclei $sub/ReconData/CustomWordlist $sub/Screenshots
#dnscan
echo "Listing Subdomains using dnscan..."
python3 /root/tools/dnscan/dnscan.py -d $sub -t 100 -o $sub/Subdomains/dnscan_out.txt -w $wordlist_dns;
# Remove headers and leading spaces
sed '1,/A records/d' $sub/Subdomains/dnscan_out.txt | tr -d ' ' > $sub/Subdomains/trimmed;
cut $sub/Subdomains/trimmed -d '-' -f 2 > $sub/Subdomains/dnscan-domains.txt;
rm $sub/Subdomains/trimmed;
# Cat output into all_subdomain
cat $sub/Subdomains/dnscan-domains.txt >> $sub/Subdomains/all_subdomain;
# Check if Ctrl+C was pressed and added to domain
grep -v 'KeyboardInterrupt' $sub/Subdomains/all_subdomain > $sub/Subdomains/tmp;
mv $sub/Subdomains/tmp $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/dnscan-domains.txt;
rm $sub/Subdomains/dnscan_out.txt


#subfinder
echo "Listing Subdomains using subfinder..."
subfinder -d $sub -o $sub/Subdomains/subfinder.txt;
#Cat output into all_subdomain
cat $sub/Subdomains/subfinder.txt >> $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/subfinder.txt
#amass
echo "Listing Subdomains using amass..."
amass enum -d $sub -brute -ipv4 -rf $resolvers -active -w $wordlist_dns -o $sub/Subdomains/amass-output.txt -min-for-recursive 3;
# Cat output into all_subdomain
cut -d ' ' -f 1 $sub/Subdomains/amass-output.txt >> $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/amass-output.txt;
#sublist3r
echo "Listing Subdomains using sublist3r..."
python3 /root/tools/Sublist3r/sublist3r.py -d $sub -v -t 100 -o $sub/Subdomains/sublist3r-output.txt;
# Cat output into all_subdomain
cat $sub/Subdomains/sublist3r-output.txt >> $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/sublist3r-output.txt;
#assetfinder
echo "Listing Subdomains using assetfinder..."
assetfinder -subs-only $sub | tee $sub/Subdomains/assetfinder.txt;
# Cat output into all_subdomain
cat $sub/Subdomains/assetfinder.txt >> $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/assetfinder.txt
#knokpy,forked
echo "Listing Subdomains using knockpy..."
knockpy $sub -w $wordlist_dns > $sub/Subdomains/knock-output.txt;
# Parse output and add to all domain and IP lists
awk -F ',' '{print $2" "$3}' $sub/Subdomains/knock-output.txt | grep -e "$DOMAIN$" > $sub/Subdomains/knock-tmp.txt;
cut -d ' ' -f 2 $sub/Subdomains/knock-tmp.txt >> $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/knock-tmp.txt;
rm $sub/Subdomains/knock-output.txt;
# Get unique domains, ignoring case
sort $sub/Subdomains/all_subdomain | uniq -i > $sub/Subdomains/temp2;
mv $sub/Subdomains/temp2 $sub/Subdomains/all_subdomain;

#findomain and discord notification
#Please chage iwas modified during adding function
echo "Listing Subdomains using findomain..."
~/tools/findomain/findomain-linux --import-subdomains $sub/Subdomains/all_subdomain -m -t $sub --aempty -c /root/.config/findomain/config.toml -u $sub/Subdomains/findomain.txt;
#Cat output into all_subdomain
cat $sub/Subdomains/findomain.txt >> $sub/Subdomains/all_subdomain;
rm $sub/Subdomains/findomain.txt;
# Get unique domains, ignoring case
sort $sub/Subdomains/all_subdomain | uniq -i > $sub/Subdomains/temp3;
mv $sub/Subdomains/temp3 $sub/Subdomains/all_subdomain;
done
}
subdomain_enum

resolve_subdomains(){
for sub in $(cat $host);
do
echo "Resolving subdomains for $sub using filter-resolved  ..."	
cat $sub/Subdomains/all_subdomain | filter-resolved > $sub/Subdomains/resolved_subdomains.txt
#rm -r /root/.gdrive/Recon-Data/$sub/Subdomains/all_subdomain
done
}
resolve_subdomains



subtko(){
for sub in $(cat $host);
do
echo "Checking subdomain take over for $sub,cross your finger..."
#https
subjack -w $sub/Subdomains/resolved_subdomains.txt -a -m -t 100 -timeout 30 -ssl -v 3 | grep -iv "Not Vulnerable" > $sub/ReconData/subjack/https_subjack.txt;
cat $sub/ReconData/subjack/https_subjack.txt > $sub/ReconData/subjack/subdomain_takeover.txt;
#http
subjack -w $sub/Subdomains/resolved_subdomains.txt -a -m -t 100 -timeout 30 -v 3 | grep -iv "Not Vulnerable" > $sub/ReconData/subjack/http_subjack.txt;
cat $sub/ReconData/subjack/http_subjack.txt >> $sub/ReconData/subjack/subdomain_takeover.txt
# Get unique results,ignoring case
sort $sub/ReconData/subjack/subdomain_takeover.txt | uniq -i > $sub/ReconData/subjack/temp4;
mv $sub/ReconData/subjack/temp4 $sub/ReconData/subjack/subdomain_takeover.txt;
#Get a notification
cat $sub/ReconData/subjack/subdomain_takeover.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/subjack/subdomain_takeover.txt > $sub/ReconData/subjack/new_subdtakeover.txt; echo "Found New Possible Subdomain Takeover For $sub" | cat - $sub/ReconData/subjack/new_subdtakeover.txt > $sub/ReconData/subjack/temp5 && mv $sub/ReconData/subjack/temp5 $sub/ReconData/subjack/new_subdtakeover.txt;cat $sub/ReconData/subjack/new_subdtakeover.txt | emissary -t -si;
rm $sub/ReconData/subjack/https_subjack.txt
rm $sub/ReconData/subjack/http_subjack.txt 
rm $sub/ReconData/subjack/new_subdtakeover.txt 
done
}
subtko

new_resolved_subdomains(){
for sub in $(cat $host);
do
echo "Searching new resolved Subdomains for $sub ..."
cat $sub/Subdomains/resolved_subdomains.txt | anew /root/.gdrive/Recon-Data/$sub/Subdomains/resolved_Subdomains > $sub/Subdomains/new_rslv_subdomain.txt;
#Get Notification
echo "New resolved subdomains for $sub , checkout quickly" | cat - $sub/Subdomains/new_rslv_subdomain.txt > $sub/Subdomains/temp9 && mv $sub/Subdomains/temp9 $sub/Subdomains/new_rslv_subdomain.txt ; cat $sub/Subdomains/new_rslv_subdomain.txt | emissary -t -si;
cat $sub/Subdomains/new_rslv_subdomain.txt

done
}
new_resolved_subdomains

http_prob(){
for sub in $(cat $host);
do
echo "Probing $sub subdomains for http/s ..."
cat $sub/Subdomains/new_rslv_subdomain.txt | httpx -threads 200 -o $sub/ReconData/httpx.txt
done
}
http_prob

wayback_data(){
for sub in $(cat $host);
do
echo "Scraping wayback data for $sub ..."
cat $sub/ReconData/httpx.txt | waybackurls | egrep -iv ".(jpg|jpeg|gif|css|tiff|png|tif|png|ttf|woff|woff2|ico|svg)" | sed 's/:80//g;s/:443//g' | sort -u > $sub/ReconData/waybackurls.txt
done
}
wayback_data

valid_waybackdata(){
for sub in $(cat $host);
do
echo "Validating wayback data for $sub ..."
ffuf -c -u "FUZZ" -w $sub/ReconData/waybackurls.txt -mc 200 -of csv -o $sub/ReconData/tmp3.txt;
cat $sub/ReconData/tmp3.txt | grep http | awk -F "," '{print $1}' >> $sub/ReconData/valid_wayback.txt
rm $sub/ReconData/tmp3.txt;
done
}
valid_waybackdata

run_CORStest(){
for sub in $(cat $host);
do
echo "Running CORStest for $sub ..."
python3 ~/tools/CORStest/corstest.py -p 64 $sub/ReconData/httpx.txt > $sub/ReconData/CORStest_output.txt;
#Get Notification of number of CORS:
cat $sub/ReconData/CORStest_output.txt | anew /root/.gdrive/Recon-data/$sub/ReconData/CORStest_output.txt > $sub/ReconData/newcors;cat $sub/ReconData/newcors | wc -l > $sub/ReconData/no_of_new_cors;echo "Number New CORS for $sub" | cat - $sub/ReconData/no_of_new_cors > $sub/ReconData/temp9 && mv $sub/ReconData/temp9 $sub/ReconData/no_of_new_cors ; cat $sub/ReconData/no_of_new_cors | emissary -t -si;
rm $sub/ReconData/no_of_new_cors;
rm $sub/ReconData/newcors;
done
}
run_CORStest

aws_scanner(){
for sub in $(cat $host);
do
echo "Searching for a broken bucket in aws using flumberbuckets ... "
python3 ~/tools/flumberboozle/flumberbuckets/flumberbuckets.py -m ~/tools/massdns/bin/massdns -w /root/tools/flumberboozle/flumberbuckets/medium.txt --resolve $resolvers -d $sub/Subdomains/new_rslv_subdomain.txt -i test -o $sub/ReconData/aws_bucket.txt;
#Get Notofication
#Get Notification of number of CORS:
cat $sub/ReconData/aws_bucket.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/aws_bucket.txt > $sub/ReconData/new_aws_bucket.txt;cat $sub/ReconData/new_aws_bucket.txt | wc -l > $sub/ReconData/no_of_new_aws_bucket.txt;echo "Number New bucket for $sub" | cat - $sub/ReconData/no_of_new_aws_bucket.txt > $sub/ReconData/temp9 && mv $sub/ReconData/temp9 $sub/ReconData/no_of_new_aws_bucket.txt ; cat $sub/ReconData/no_of_new_aws_bucket.txt | emissary -t -si;
rm $sub/ReconData/no_of_new_aws_bucket.txt;
rm $sub/ReconData/new_aws_bucket.txt;
done
}
aws_scanner

scanner(){
for sub in $(cat $host);
do
echo "Iniatiating nuclei scanner for $sub ..."
echo "Running exposed-token templates for $sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/exposed-tokens/ -silent -c 50 | tee $sub/ReconData/nuclei/token-nuclei.txt
echo "Running subtko templates for $sub .."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/takeovers/ -silent -c 50 | tee $sub/ReconData/nuclei/stko-nuclei.txt
echo "Running files templates for $sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/exposures/files/ -silent -c 50 | tee $sub/ReconData/nuclei/files-nuclei.txt
echo "Running cve templates for $sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/cves/ -silent -c 50 | tee  $sub/ReconData/nuclei/cves-nuclei.txt
echo "Running vulns templates for $sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/vulnerabilities/ -silent -c 50 | tee $sub/ReconData/nuclei/vulns-nuclei.txt
echo "Checking security misfiguration for $sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/misconfiguration/ -silent -c 20 | tee $sub/ReconData/nuclei/misconfig-nuclei.txt
echo "Running tech templates for$sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/technologies/ -silent -c 50 | tee $sub/ReconData/nuclei/tech-nuclei.txt
echo "Running panel templates for $sub ..."
nuclei -l $sub/ReconData/httpx.txt -t /root/nuclei-templates/exposed-panels/ -silent -c 50 | tee $sub/ReconData/nuclei/panels-nuclei.txt
#Get notofocations
#Get Notification of number of CORS:
cat $sub/ReconData/nuclei/*nuclei.txt >> $sub/ReconData/nuclei/new_nuclei.txt
cat $sub/ReconData/nuclei/new_nuclei.txt | wc -l > $sub/ReconData/nuclei/no_of_new_nuclei.txt;echo "No. of new vulns nuclei found for $sub" | cat - $sub/ReconData/nuclei/no_of_new_nuclei.txt > $sub/ReconData/nuclei/temp9 && mv $sub/ReconData/nuclei/temp9 $sub/ReconData/nuclei/no_of_new_nuclei.txt ; cat $sub/ReconData/nuclei/no_of_new_nuclei.txt | emissary -t -si; 
done
}
scanner

CustomWordlist(){
for sub in $(cat $host);
do
echo "Creating new custom wordlist for $sub ..."
cat $sub/ReconData/waybackurls.txt | unfurl --unique paths | tee $sub/ReconData/CustomWordlist/paths.txt
cat $sub/ReconData/waybackurls.txt | unfurl --unique keys | tee $sub/ReconData/CustomWordlist/params.txt
cat $sub/ReconData/waybackurls.txt | unfurl --unique values | tee $sub/ReconData/CustomWordlist/values.txt
cat $sub/ReconData/waybackurls.txt | unfurl --unique keypairs | tee $sub/ReconData/CustomWordlist/keypairs.txt
#Get Notification of number of CORS:
cat $sub/ReconData/CustomWordlist/paths.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/CustomWordlist/paths.txt > $sub/ReconData/CustomWordlist/newpaths_cw.txt
cat $sub/ReconData/CustomWordlist/params.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/CustomWordlist/params.txt > $sub/ReconData/CustomWordlist/newparams_cw.txt
cat $sub/ReconData/CustomWordlist/values.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/CustomWordlist/values.txt > $sub/ReconData/CustomWordlist/new values_cw.txt
cat $sub/ReconData/CustomWordlist/keypairs.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/CustomWordlist/keypairs.txt > $sub/ReconData/CustomWordlist/newkeys_cw.txt
cat $sub/ReconData/CustomWordlist/*_cw.txt > $sub/ReconData/CustomWordlist/new_params.txt;cat $sub/ReconData/CustomWordlist/new_params.txt | wc -l > $sub/ReconData/CustomWordlist/no_of_newparams.txt;echo "No. of new params found for $sub" | cat - $sub/ReconData/CustomWordlist/no_of_newparams.txt > $sub/ReconData/CustomWordlist/tmp13 && mv $sub/ReconData/CustomWordlist/tmp13 $sub/ReconData/nuclei/no_of_new_nuclei.txt ; cat $sub/ReconData/CustomWordlist/no_of_newparams.txt | emissary -t -si;
rm $sub/ReconData/CustomWordlist/*.txt
done
}
CustomWordlist

broken_link_scanner(){
for sub in $(cat $host);
do
echo "Checking for broken link with blc in $sub and its subdomains "
blc -rfoi --exclude youtube.com --filter-level 3 $sub/ReconData/httpx.txt | grep "BROKEN" > $sub/ReconData/blc_output.txt
#Get Notification of number of new broken link found:
cat $sub/ReconData/blc_output.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/blc_output.txt > $sub/ReconData/new_brokenlink.txt; cat $sub/ReconData/new_brokenlink.txt| wc -l > $sub/ReconData/no_of_broken_link.txt; echo "Number New brokenlink For $sub" | cat - $sub/ReconData/no_of_broken_link.txt > $sub/ReconData/temp5 && mv $sub/ReconData/temp5 $sub/ReconData/no_of_broken_link.txt ; cat $sub/ReconData/no_of_broken_link.txt | emissary -t -si;
rm $sub/ReconData/no_of_broken_link.txt;
rm $sub/ReconData/new_brokenlink.txt;
done
}
broken_link_scanner

keyfinding(){
for sub in $(cat $host);
do
echo "Scraping for keys from $sub with Subdomainizer"
echo "Subdomainizer gives many false positive it's always a good idea to check them with meg and gf patterns manually"
python3 ~/tools/SubDomainizer/SubDomainizer.py -l $sub/ReconData/httpx.txt -o $sub/ReconData/Subdomainizer.txt -gt f64827dd745bc1fef554585ff64cb40d90924d38 -g -k -san all 
#Get notifications
cat $sub/ReconData/Subdomainizer.txt | anew /root/.gdrive/Recon-Data/$sub/ReconData/Subdomainizer.txt > $sub/ReconData/new_Subdomainizer.txt; cat $sub/ReconData/new_Subdomainizer.txt | wc -l > $sub/ReconData/no_new_Subdomainizer.txt;echo "Number New keys found for $sub (with Subdomainizers)" | cat - $sub/ReconData/no_new_Subdomainizer.txt > $sub/ReconData/tmp20 && mv $sub/ReconData/tmp20 $sub/ReconData/no_new_Subdomainizer.txt ; cat $sub/ReconData/no_new_Subdomainizer.txt | emissary -t -si;
rm $sub/ReconData/new_Subdomainizer.txt
rm $sub/ReconData/no_new_Subdomainizer.txt
done
}
keyfinding

delete_folders(){
for sub in $(cat $host);
do
echo "Deleting Folders..."
rm -r $sub
done
}
delete_folders

echo "Recon is completed,don't forget to check outputs..."
emissary -t -m "Informer completed his cronjobs for you,Don't forget to check resuls,You may find some juicy stuffs"
#Use find to delete all.txt
