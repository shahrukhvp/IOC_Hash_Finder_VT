$api_Key="a86c11b36346da6309f284a270b80ace7a38139de3a35920bc53b35bc5aba07d"
$IOC_Hash="9d38a0220b2dfb353fc34d03079f2ba2c7de1d4a234f6a2b06365bfc1870cd89"
$IOC_Hash=0
$Out_Dir="C:\IOC_Finder"
$Out_CSV="C:\IOC_Finder\IOC_Hash_Finder.csv"
$temp_File="C:\IOC_Finder\Temp.txt"
$Input_File="C:\IOC_Finder\Input.txt"
[system.io.directory]::CreateDirectory("$Out_Dir")
Write-Host "md5                               sha1                                      sha256"
foreach($line in [System.IO.File]::ReadLines($Input_File))
{
    $IOC_Hash=$line
    $R=Invoke-WebRequest -Method Get -URI https://www.virustotal.com/vtapi/v2/file/report?apikey=$api_Key"&"resource=$IOC_Hash
    $R2=0
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
        {Write-Host "Error: IOC Hash '$IOC_Hash' was not found in VirusTotal or The API Key limit is exceeded"}
    else{Write-Host "$md5  $sha1  $sha256"}
    Start-Sleep -s 16
}
