$results = @()
$api_Key="a86c11b36346da6309f284a270b80ace7a38139de3a35920bc53b35bc5aba07d"
$IOC_Hash=0
$Out_Dir="C:\IOC_Finder"
$temp_File="C:\IOC_Finder\Temp.txt"
$Hashes_Input_File="C:\IOC_Finder\Input.txt"
$Output_Match_Error="C:\IOC_Finder\Output_No_Match_Hashes.txt"
$Output_Match_Success="C:\IOC_Finder\Output_Matched_Hashes.csv"
$Hashes_Match_Success_Count=0
$Hashes_Match_Error_Count=0
$Hashes_Input_Count=0
[system.io.directory]::CreateDirectory("$Out_Dir")
if (Test-Path $Hashes_Input_File) 
    { 
    "Error: The below hashes were not found in VirusTotal:" | Out-File -filepath $Output_Match_Error
    Write-Host "md5                               sha1                                      sha256"
    foreach($IOC_Hash in [System.IO.File]::ReadLines($Hashes_Input_File))
        {
        $Hashes_Input_Count+=1
        $R2=0
        $R=Invoke-WebRequest -Method Get -URI https://www.virustotal.com/vtapi/v2/file/report?apikey=$api_Key"&"resource=$IOC_Hash
        $R2=$R.AllElements | %{$_ -replace "}","}`r`n"}
        $R2 | Out-File -filepath $temp_File
        $R3= Get-Content $temp_File | Select-String -Pattern "scan_id" | Get-Unique
        $R3 | Out-File -filepath $temp_File
        $R3 = $R3 | %{$_ -replace ",","`r`n"}
        $R3 | Out-File -filepath $temp_File
        $sha1= Get-Content $temp_File | Select-String -Pattern "sha1"
        $sha1= $sha1 | %{$_ -replace " ",""}
        $sha1= $sha1 | %{$_ -replace "}",""}
        $sha1= $sha1 | %{$_ -replace "sha1",""}
        $sha1= $sha1 | %{$_ -replace '"',""}
        $sha1= $sha1 | %{$_ -replace ":",""}
        $sha256= Get-Content $temp_File | Select-String -Pattern "sha256"
        $sha256= $sha256 | %{$_ -replace " ",""}
        $sha256= $sha256 | %{$_ -replace "}",""}
        $sha256= $sha256 | %{$_ -replace "sha256",""}
        $sha256= $sha256 | %{$_ -replace '"',""}
        $sha256= $sha256 | %{$_ -replace ":",""}
        $md5= Get-Content $temp_File | Select-String -Pattern "md5"
        $md5= $md5 | %{$_ -replace " ",""}
        $md5= $md5 | %{$_ -replace "}",""}
        $md5= $md5 | %{$_ -replace "md5",""}
        $md5= $md5 | %{$_ -replace '"',""}
        $md5= $md5 | %{$_ -replace ":",""}
        if ([string]::IsNullOrEmpty($md5))
            {
            $Hashes_Match_Error_Count+=1
            Write-Host "Error: IOC Hash '$IOC_Hash' was not found in VirusTotal"
            $IOC_Hash | Out-File -filepath $Output_Match_Error -Append
            }
        else{
            $Hashes_Match_Success_Count+=1
            Write-Host "$md5  $sha1  $sha256"
            #"$md5  $sha1  $sha256" | Out-File -filepath $Output_Match_Success -Append
            $hashes = @{            
                    MD5   = $md5              
                    SHA1  = $sha1
                    SHA256= $sha256
                    }
            $results += New-Object PSObject -Property $hashes
            }
        #Start-Sleep -s 16
        }
    $results | export-csv -Path $Output_Match_Success -NoTypeInformation
    Write-Host "Number of Hashes read from input file     : '$Hashes_Input_Count'"
    Write-Host "Number of Hashes matched in VirusTotal    : '$Hashes_Match_Success_Count'"
    Write-Host "Number of Hashes not matched in VirusTotal: '$Hashes_Match_Error_Count'"
    del $temp_File
    }
else
    {
    Write-Host "Error: Input file was not found. Please keep the input files with hash values in the '$Out_Dir' with name 'Input.txt' "
    }
