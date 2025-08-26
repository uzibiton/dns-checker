* Read pcap file. (use python generator)
* For each dns pkt retrive the domain
* For each domain, Check in cache or send to the Ranking service (Use API call snet to Mock)
* Save results in cache if the domain is not there.
* While Reading the file/intr get the statistics: Number of pkt, Error (not sure what kind of errors), DNS (Query rate).
* The reading of the packets & the API calls should run in differet threads 


Questions - 
* The mock returns different result for the same domain name. So, I assumed that the first result should be saved and when the same domain appers again I pull the result from the cache.
* To initiate a DNS request - nslookup google.com