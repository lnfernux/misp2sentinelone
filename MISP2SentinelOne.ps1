param( 
    # MISP configuration
    $MISPURL = "https://misp.local",
    $MISPKey = "123123123",
    $MISPFilters = @{
        "tags" = @("tlp:green", "tlp:clear", "tlp:white")
    },
    # SentinelOne configuration
    $SentinelOneURL = "https://dummy.sentinelone.net/",
    $SentinelOneAPIKey = "123123123",
    $ValidUntilDays = 14,
    $SiteId = "123123123"
)

# Function to download indicators of compromise from MISP
function Get-Events {
    param(
        $MISPKey,
        $MISPURL,
        $MISPFilters
    )
    $Headers = @{
        "Authorization" = $MISPKey
        "Accept" = "application/json"
    }
    $Data = @{
        "timestamp" = "1d"
    }
    foreach ($Key in $MISPFilters.Keys) {
        $Data[$Key] = $MISPFilters[$Key]
    }

    $Response = Invoke-RestMethod -Uri "$MISPURL/events/restSearch" -Method POST -Headers $Headers -ContentType "application/json" -Body ($Data | ConvertTo-Json)
    if ($Response) {
        return $Response
    } else {
        Write-Host "Failed to download indicators from MISP."
        return $null
    }
}

# Function to parse the downloaded events
function Parse-Events {
    param (
        [Parameter(Mandatory=$true)]
        [array]$EventArray,
        [Parameter(Mandatory=$false)]
        [array]$includedHashTypes = @("md5", "sha1", "sha256"),
        [Parameter(Mandatory=$false)]
        [array]$includedNetworkTypes = @("ip-src", "ip-dst", "domain", "url", "domain|ip", "hostname|ip"),
        [Parameter(Mandatory=$false)]
        $ValidUntilDays
    )

    $ParsedEvents = @()
    foreach ($Event in $EventArray.response.event) {
        $ParsedEvent = @{
            "indicator" = ""
            "type" = ""
            "validUntil" = (Get-Date).AddDays($ValidUntilDays).ToUniversalTime().ToString("s")
        }
        foreach ($Attribute in $Event.Attribute) {
            if ($Attribute.type -in $includedNetworkTypes) {
                $ParsedEvent.indicator = $Attribute.value
                $ParsedEvent.type = $Attribute.type
            } elseif ($Attribute.type -in $includedHashTypes) {
                $ParsedEvent.indicator = $Attribute.value
                $ParsedEvent.type = "hash"
            }
        }
        $ParsedEvents += $ParsedEvent
    }
    return $ParsedEvents
}

# Function to send parsed events to SentinelOne
function Send-ToSentinelOne {
    param (
        [Parameter(Mandatory=$true)]
        [array]$ParsedEvents,
        [Parameter(Mandatory=$true)]
        $SentinelOneAPIKey,
        [Parameter(Mandatory=$true)]
        $SentinelOneURL,
        $SiteID
    )
    $ThreatIntelUrl = $SentinelOneURL+"web/api/v2.1/threat-intelligence/iocs"
    $Headers = @{
        "Authorization" = "ApiToken $SentinelOneAPIKey"
        "Content-Type" = "application/json"
    }
    $JsonPayload = @'
    {
        "filter": {
          "siteIds": ["$SiteID"]
        },
        "data": [
          {
            "source": "MISP",
            "method": "EQUALS",
            "type": "###TYPE###",
            "value": "###INDICATOR###",
            "validUntil": "###VALIDUNTIL###"
          }
        ]
      }
'@
    foreach ($ParsedEvent in $ParsedEvents) {
        $JsonPayload = $JsonPayload -replace "###TYPE###", $ParsedEvent.type
        $JsonPayload = $JsonPayload -replace "###INDICATOR###", $ParsedEvent.indicator
        $JsonPayload = $JsonPayload -replace "###VALIDUNTIL###", $ParsedEvent.validUntil 
    }
    $Response = Invoke-RestMethod -Uri $ThreatIntelUrl -Method POST -Headers $Headers -Body $Payload
    if ($Response.StatusCode -ne 200) {
        Write-Host "Failed to send indicator to SentinelOne. Status code: $($Response.StatusCode)"
    }
}

# Main script

# Get all events based on the filter
$EventArray = Get-Events -MISPKey $MISPKey -MISPURL $MISPURL -MISPFilters $MISPFilters

# Parse the events
$ParsedEvents = Parse-Events -EventArray $EventArray -ValidUntilDays $ValidUntilDays

# Send to SentinelOne
Send-ToSentinelOne -ParsedEvents $ParsedEvents -SentinelOneAPIKey $SentinelOneAPIKey -SentinelOneURL $SentinelOneURL -SiteId $SiteID
