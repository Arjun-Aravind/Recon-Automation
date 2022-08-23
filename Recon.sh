#!/bin/bash
domain=$1
wordlist="~/tools/SecLists/Discovery/DNS/clean-jhaddix-dns.txt"
resolvers="~/tools/dnsvalidator/resolvers.txt"

domain_enum(){
mkdir -p $domain $domain/subdomains $domain/Recon $domain/Recon/nuclei $domain/Recon/waybackurls $domain/Recon/gf
subfinder -d $domain -all -o $domain/subdomains/subf-subs.txt
assetfinder -subs-only $domain | tee $domain/subdomains/asset-subs.txt
amass enum -passive -d $domain -o $domain/subdomains/amass-subs.txt
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/subdomains/shuffledns.txt
cat $domain/subdomains/*.txt > $domain/subdomains/all-subs.txt
}
domain_enum

resolving_domains(){
shuffledns -d $domain -list $domain/subdomains/all-subs.txt -o $domain/domains.txt -r $resolvers
}
resolving_domains

http_probe(){
cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
}
http_probe

nuclei_scanner(){
cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt
cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilities.txt
cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/files/ -c 50 -o $domain/Recon/nuclei/files.txt
cat $domain/Recon/httpx.txt | nuclei -t ~/nuclei-templates/takeovers/ -c 50 -o $domain/Recon/nuclei/takeovers.txt
}
nuclei_scanner

wayback_data(){
cat $domain/domains.txt | waybackurls | tee $domain/Recon/waybackurls/tmp.txt
cat $domain/Recon/waybackurls/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.gif|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/Recon/waybackurls/urls.txt
}
wayback_data

valid_url(){
cat $domain/Recon/waybackurls/urls.txt | urlprobe -c 1000 -t 01 | grep 200 | awk '{print $5}' | tee -a  $domain/Recon/waybackurls/valid-urls.txt 
}
valid_url

gf_patterns(){
gf xss $domain/Recon/waybackurls/urls.txt | tee $domain/Recon/gf/xss.txt
gf sqli $domain/Recon/waybackurls/urls.txt | tee $domain/Recon/gf/sql.txt
}
gf_patterns