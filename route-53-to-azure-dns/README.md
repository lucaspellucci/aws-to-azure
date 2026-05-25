# route-53-to-azure-dns

Generate an Azure DNS Bicep template from an AWS Route53 hosted zone.

The script reads every record set in a Route53 hosted zone via the AWS API and
emits a Bicep file declaring the Azure DNS zone plus one resource per
migrate-able record. Anything that can't be translated cleanly (Route53 routing
policies, out-of-zone aliases, deprecated types) is logged to stderr **and**
emitted as a `// SKIPPED` or `// NOTE` comment in the Bicep output so it shows
up at review time.

The script never calls Azure. It only writes a template you deploy yourself.

## Requirements

- Python 3.10+
- `pip install boto3`
- AWS credentials with `route53:GetHostedZone` and
  `route53:ListResourceRecordSets`. The script uses the boto3 default
  credential chain (env vars, `~/.aws/credentials`, IAM role, SSO) or
  `--aws-profile <name>`.
- Azure CLI (or Bicep CLI) on whatever machine deploys the generated template.

## Usage

```
python route-53-to-azure-dns.py \
    --source-zone <ZONE_ID> \
    [--output <file.bicep>] \
    [--zone-name <azure-zone-name>] \
    [--alias-to-cname] \
    [--aws-profile <name>] \
    [--verbose]
```

### Arguments

| Flag | Description |
| ---- | ----------- |
| `--source-zone` | **Required.** Route53 hosted zone ID, e.g. `Z1234567890ABC` or `/hostedzone/Z1234567890ABC`. DNS names are **not** accepted — look the ID up first with `aws route53 list-hosted-zones`. |
| `--output`, `-o` | Output Bicep file path. Defaults to `<zone-name>.bicep` in the current directory. |
| `--zone-name` | Azure DNS zone name used in the template. Defaults to the Route53 zone's DNS name (trailing dot stripped). |
| `--alias-to-cname` | Last-resort fallback for aliases that are neither in-zone nor DNS-resolvable: convert to CNAME (skipped at the apex per RFC 1034). In-zone aliases are always emitted as Azure DNS alias records; out-of-zone aliases are DNS-resolved and pinned as A/AAAA first. |
| `--aws-profile` | Named AWS profile to use. |
| `--verbose`, `-v` | Verbose logging. Without it, only warnings and errors are shown (red on a terminal; set `NO_COLOR=1` to disable color). |

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Success |
| `1` | Route53 / AWS error |
| `2` | Invalid `--source-zone` format |

## Examples

Look up the zone ID first if you only know the domain name:

```
aws route53 list-hosted-zones \
    --query "HostedZones[?Name=='example.com.'].Id" --output text
```

Default run — writes `./<zone-name>.bicep`, only warnings/errors on stderr:

```
python route-53-to-azure-dns.py --source-zone Z1234567890ABC
```

Custom output path, custom Azure zone name, named AWS profile, and convert
out-of-zone aliases to CNAMEs:

```
python route-53-to-azure-dns.py \
    --source-zone Z1234567890ABC \
    --output example.bicep \
    --zone-name example.com \
    --alias-to-cname \
    --aws-profile production
```

Verbose run for the example zone bundled with this repo:

```
python route-53-to-azure-dns.py \
    --source-zone Z02448521Y0N9XWNV0DRX \
    --aws-profile arara-full \
    --alias-to-cname \
    --verbose
```

## Deploying the generated template

```
az deployment group create \
    --resource-group <rg> \
    --template-file example.bicep \
    --parameters zoneName=example.com
```

After the deployment succeeds, list the Azure-assigned name servers so you can
update your registrar:

```
az network dns zone show \
    --resource-group <rg> \
    --name example.com \
    --query nameServers --output tsv
```

## How records are translated

| Route53 input | Result |
| ------------- | ------ |
| Supported types (A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT) | Emitted as the matching `Microsoft.Network/dnsZones/<TYPE>` resource. |
| Apex `SOA` / `NS` | Skipped — Azure DNS manages these automatically. |
| `SPF` (RR type 99) | Converted to `TXT` at the same name. Skipped if a `TXT` already exists there (avoids silently overwriting it). |
| Alias record, target in the same zone (A/AAAA/CNAME) | Emitted as an Azure DNS alias record set whose `targetResource.id` points at the local target's Bicep resource. Works at the apex. |
| Alias record, target out-of-zone (or in-zone with no matching type) | DNS-resolved via the system resolver and pinned as a normal A/AAAA record. Re-run if upstream IPs change. |
| Alias record, neither in-zone nor DNS-resolvable | Skipped by default; with `--alias-to-cname`, converted to CNAME (except at the apex). |
| Weighted / Latency / Failover / Geolocation / Geoproximity / Multivalue / `SetIdentifier` | Skipped — Azure DNS has no equivalent. Use Azure Traffic Manager or Front Door. |
| Any other type | Skipped as unsupported by Azure DNS. |

Every skipped or converted record appears as a `// SKIPPED` or `// NOTE`
comment in the Bicep output, so you can review the gaps before deploying.
