# IOC_Hash_Finder_VT
The power shell script reads multiple MD5, SHA1 or SHA256 hash values line by line from a file and search for it's corresponding hash values with the help of VirusTotal Database. 
Before you run the script, please Create the following folder: "C:\VT_IOC_Hash_Matcher"
And, rename your input file with hash values to "Input.txt" and copy the file to the folder: "C:\VT_IOC_Hash_Matcher"
Run the script, you may find two output files inside the folder "C:\VT_IOC_Hash_Matcher" with names:
    1. Output_Matched_Hashes.csv (Contains all matched hash values and their corresponding hashes")
    2. Output_No_Match_Hashes.txt (Contains all hash values which were not a match in VirusTotal)
Happy IOC Hunting.

Queries:
https://www.linkedin.com/in/iamshahrukh/


