# @post
# Get current datetime in UTC
$dtg = Get-Date -Format "ddHHmmZMMMyy"

# Grab input from user for file to be analyzed for IOCs
$file_path = Read-Host "Name of file to perform analysis on"

# Global variable for storing all IOCs
$ioc_list = Get-Content $file_path

# File for all analysis to be written to
$new_file_path = "Vetted_IOCs_${dtg}.docx"

function VirusTotalIP {
    param ($ioc)
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$ioc"
    $headers = @{
        "accept"   = "application/json"
        "x-apikey" = "<VirusTotalKey"
    }
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    if ($response.data.type -contains "ip_address") {
        $totalScore = $response.data.attributes.last_analysis_stats.harmless + $response.data.attributes.last_analysis_stats.malicious + $response.data.attributes.last_analysis_stats.suspicious + $response.data.attributes.last_analysis_stats.undetected
        $finalRating = "{0}/{1}" -f $response.data.attributes.total_votes.malicious, $totalScore
        Add-Content -Path $new_file_path -Value "`t`tVirusTotal: $finalRating"
    } 
    else { Add-Content -Path $new_file_path -Value "`t`tVirusTotal: No record found" }
}

function VirusTotalDomain {
    param ($ioc)
    $url = "https://www.virustotal.com/api/v3/domains/$ioc"

    $headers = @{
        "accept"   = "application/json"
        "x-apikey" = "<VirusTotalKey>"
    }

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    if ($response.data.type -eq "domain") {
        $totalScore = $response.data.attributes.last_analysis_stats.harmless + $response.data.attributes.last_analysis_stats.malicious + $response.data.attributes.last_analysis_stats.suspicious + $response.data.attributes.last_analysis_stats.undetected
        $finalRating = "{0}/{1}" -f $response.data.attributes.last_analysis_stats.malicious, $totalScore
        Add-Content -Path $new_file_path -Value "`t`tVirusTotal: $finalRating"
    } else { Add-Content -Path $new_file_path -Value "`t`tVirusTotal: No record found" }
}

function MandiantAnalysis {
    param ($ioc)
    Add-Content -Path $new_file_path -Value "`t`tMandiant: [Placeholder]"
}

function RecordedFuture {
    param ($ioc)
    Add-Content -Path $new_file_path -Value "`t`tRF: [Placeholder]`n"
}

function Fusion {
    # TBD
}

# Perform analysis and write to the new file 
foreach ($ioc in $ioc_list) {
    $ioc = $ioc.Trim()

    if ($ioc -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
        Add-Content -Path $new_file_path -Value "`t$ioc"
        VirusTotalIP $ioc
        MandiantAnalysis $ioc
        RecordedFuture $ioc
        # FusionAnalysis $ioc
    } elseif ($ioc -match "([a-z0-9\-]*\.)*([a-z0-9\-]*)\.[0-9a-z]{2,}") {
        Add-Content -Path $new_file_path -Value "`t$ioc"
        VirusTotalDomain $ioc
        MandiantAnalysis $ioc
        RecordedFuture $ioc
        # FusionAnalysis $ioc
    } else {
        Add-Content -Path $new_file_path -Value $ioc
    }
}
