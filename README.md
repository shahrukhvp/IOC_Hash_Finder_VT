# IOC_Hash_Finder_VT
The power shell script reads multiple MD5, SHA1 or SHA256 hash values line by line from a file and search for it's corresponding hash values with the help of VirusTotal Database. 
Before you run the script, please:
    
1.  Create the following folder: "C:\VT_IOC_Hash_Matcher"
    
2.  SignUp in VirusTotal.com to get the API_KEY, which is mandatory to send any requests to VirusTotal. Copy the API_Key in the downloaded file "VT_API_KEY.conf" and copy the file to "C:\VT_IOC_Hash_Matcher". 
    
3.  Rename your input file (with hash values) to "Input.txt". Hash values must be given in the file in line by line basis.
    
4.  Copy the input file to the folder: "C:\VT_IOC_Hash_Matcher"
    
5.  Make sure you have write permissions for the folder "C:\VT_IOC_Hash_Matcher", before you run the Sctipt.
    
6.  Run the script. Once the script is finished, you may find two output files inside the folder "C:\VT_IOC_Hash_Matcher" with names:
            
	a. Output_Matched_Hashes.csv (Contains all matched hash values and their corresponding hashes")
            
	b. Output_No_Match_Hashes.txt (Contains all hash values which were not a match in VirusTotal)



Note: The VirusTotal limits the request to the website using an API Key as 4 requests per minute. Hence, to have 12 number of hashes searched, the script requires (12/4)=3 minutes to complete. In case you have a Premium API Key bought from VirusTotal, which comes with no restrictions on the number of requests to VirusTotal.com, feel free to get rid of the code which makes the script wait for 16 seconds after every request. 

In case the powershell scripts are disabled to run in your machine, change the execution policy as follows:

		set-executionpolicy -scope CurrentUser -ExecutionPolicy Unrestricted

If you have never run internet explorer in the machine, run it and complete the initial setup steps.


Queries:
https://www.linkedin.com/in/iamshahrukh/
