# misp2sentinelone

Proof of concept code in Powershell from downloading indicators from MISP and sending them to the SentinelOne ThreatIntelligence module, Singularity.

## MISP2Sentinel.ps1

```powershell
./MISP2Sentinel.ps1 -MISPKey 12345678910 -MISPURL misp.local -SentinelOneURL sentinelone.dummy.net -SentinelOneAPIKey 123812381238 -ValidUntilDays 14 -SiteID 123123123123
```

Consist of the following functions:

### `Get-Events` 

Downloads events from MISP and takes the following parameters:

  - $MISPKey - this is the MISP API Key
  - $MISPFilters - similar to the [misp2sentinel](https://github.com/cudeso/misp2sentinel) filters, takes an json object with filters, defaults to `"tags" = @("tlp:green", "tlp:clear", "tlp:white")` just for testing
  - $MISPURL - this is the URI to your MISP server

  ```powershell
  $EventArray = Get-Events -MISPKey 12345678910 -MISPURL misp.local -MISPFilters @{"tags" = @("tlp:green","tlp:clear"),"enforce_warninglist" = True}
  ```
### `Parse-Events`

Takes the output from `Get-Events` and parses them to work with SentinelOne:

  - $EventArray - the output from `Get-Events`
  - $IncludedHashtypes - which hash type indicators to include (defaults to `md5`, `sha1` and `sha256`)
  - $IncludedNetworkTypes - same as above, for network (defaults to `ip-src`, `ip-dst`, `domain`, `url`)
  - $ValidUntilDays - number of days the indicators stays valid (defaults to 14)

  ```powershell
  $ParsedEvents = Parse-Events -EventArray $EventArray -ValidUntilDays 14
  ```
*Literally no thought has gone into which hashes and network types to include.*

### `Send-ToSentinelOne`

Takes the `SentinelOneURL` and `SentinelOneAPIKey` as input along with the `$ParsedEvents` from the `Parse-Events` function. It also needs a `$SiteId`, but this can also be changed to group or account id. Just for filtering which groups to send the data to.

```powershell
Send-ToSentinelOne -ParsedEvents $ParsedEvents -SentinelOneURL sentinelone.dummy.net -SentinelOneAPIKey 123812381238
```

### Request sample

```json
{
	"filter": {
		"accountIds": [
			{
				"type": "string",
				"minimum": 100000000000000000,
				"example": "225494730938493804"
			}
		],
		"tenant": "boolean",
		"groupIds": [
			{
				"type": "string",
				"minimum": 100000000000000000,
				"example": "225494730938493804"
			}
		],
		"siteIds": [
			{
				"type": "string",
				"minimum": 100000000000000000,
				"example": "225494730938493804"
			}
		]
	},
	"data": [
		{
			"reference": [
				{
					"type": "string",
					"x-nullable": true,
					"description": "External reference associated with the Threat Intelligence indicator"
				}
			],
			"source": "string",
			"method": "EQUALS",
			"externalId": "string",
			"pattern": "string",
			"type": "DNS",
			"name": "string",
			"intrusionSets": [
				{
					"type": "string"
				}
			],
			"patternType": "string",
			"creationTime": "2018-02-27T04:49:26.257525Z",
			"description": "string",
			"metadata": "string",
			"threatActors": [
				{
					"type": "string"
				}
			],
			"value": "string",
			"mitreTactic": [
				{
					"type": "string"
				}
			],
			"creator": "string",
			"validUntil": "2018-02-27T04:49:26.257525Z",
			"category": [
				{
					"type": "string",
					"x-nullable": true,
					"description": "The categories of the Threat Intelligence indicator, e.g.  the malware type associated with the IOC"
				}
			]
		}
	]
}
```
