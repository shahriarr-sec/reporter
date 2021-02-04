# reporter

#Recron Script xD

A script to set as your cronjob.


Every Wednesday at 5 A.M (once in a week):

0 5 * * 3 cd ~/tools/reporter/ ; sh reporter.sh domains.lst

Everyday at 12 A.M:


0 0 * * * cd ~/tools/reporter/ ; sh reporter.sh domains.lst






Install:

git clone https://github.com/shahriarr-sec/reporter.git; cd reporter; chmod +x installer.sh; ./installer.sh

Uasage: ./reporter.sh domains.lst

The domains.lst should contain only domain name

cat domains.lst example.com

www.target.com

#Tools That I used

dnscan

subfinder

amass

sublister

assetfinder

knockpy,forked

findomain

filter-resolved

subjack

httpx

waybackurls

ffuf

CORStest

flumberbuckets

unfurl

Arjun

nuclei

burl

anew

gowitness

blc

Subdomainizers

Emissary

#Infuture I will add in informer

LinkFinder

FeroxBuster

#TOMNOMNOM (Used in manual testing)

b64d

comb

ettu

tko

get-title (cat urls.txt | get-title) \handy in manual test

html-comments \handy in manual test

girtree https://github.com/tomnomnom/hacks/tree/master/gittrees

qsreplace

kxss

tok

urinteresting \helps to priotize manual testing

meg

gf

All the credit goes to the creator of these tools.Thank you for making life easier.
