# DNS command extension coverage

Guard matches DNS mutations from parsed command structure. Each cloud CLI has its own extension so
Route 53, Cloud DNS, and Azure DNS can be reviewed, labeled, and controlled independently.

Rules require a recognized executable and exact operation path. List, describe, show, and help
commands remain safe.

## Extensions

| Extension | Reviewed operations | Safe counterparts |
| --- | --- | --- |
| `command.dns.aws` | Route 53 hosted-zone, record-change, health-check, traffic-policy, DNSSEC, and Resolver deletions | List, get, and help |
| `command.dns.gcp` | Cloud DNS managed-zone, record-set, policy, and response-policy deletions and updates | Describe, list, and help |
| `command.dns.azure` | Public DNS zone and record-set deletion, private DNS zone, record-set, and VNet-link deletion, and DNS resolver deletion | Show, list, and help |

Provider-global account, project, subscription, region, output, query, and authentication options are
normalized before matching.

## Primary command references

- Amazon Route 53: [hosted-zone deletion](https://docs.aws.amazon.com/cli/latest/reference/route53/delete-hosted-zone.html),
  [record changes](https://docs.aws.amazon.com/cli/latest/reference/route53/change-resource-record-sets.html), and
  [Resolver](https://docs.aws.amazon.com/cli/latest/reference/route53resolver/index.html).
- Google Cloud DNS: [managed-zones](https://cloud.google.com/sdk/gcloud/reference/dns/managed-zones/delete),
  [record-sets](https://cloud.google.com/sdk/gcloud/reference/dns/record-sets/delete), and
  [policies](https://cloud.google.com/sdk/gcloud/reference/dns/policies/delete).
- Azure DNS: [public zones](https://learn.microsoft.com/cli/azure/network/dns/zone),
  [private zones](https://learn.microsoft.com/cli/azure/network/private-dns/zone), and
  [DNS resolver](https://learn.microsoft.com/cli/azure/dns-resolver).
