# Managed service command extension coverage

Guard matches destructive managed-service operations from parsed command structure. Rules require a recognized
executable and exact operation path; quoted examples and unrelated read or update commands remain safe.

## Extensions

| Extension | Reviewed operations | Safe counterparts |
| --- | --- | --- |
| `command.dns` | Hosted-zone deletion through AWS, Google Cloud, and Azure CLIs | List, describe, show, and help |
| `command.cdn` | Distribution, profile, and endpoint deletion through AWS and Azure CLIs | List, show, and help |
| `command.api-gateway` | API and gateway deletion through AWS, Google Cloud, and Azure CLIs | Get, list, describe, and help |
| `command.load-balancer` | Load-balancer and forwarding-rule deletion through AWS, Google Cloud, and Azure CLIs | Describe, list, show, and help |
| `command.monitoring` | Alarm and alert deletion through AWS, Google Cloud, and Azure CLIs | Describe, list, show, and help |
| `command.email` | Email identity and contact-list deletion through AWS CLI | Get, list, and help |
| `command.feature-flags` | Permanent feature-flag deletion through `ldcli` | Get, list, update/archive, and help |
| `command.payment` | Product, coupon, customer, and webhook endpoint deletion through Stripe CLI | Retrieve, list, update/archive, and help |

Provider-global account, project, subscription, region, output, query, and authentication options are normalized
before matching. Payment coverage intentionally excludes cancellation and refund commands because those operations
have distinct business and recovery semantics.

## Primary command references

- DNS: [AWS Route 53](https://docs.aws.amazon.com/cli/latest/reference/route53/delete-hosted-zone.html),
  [Google Cloud DNS](https://cloud.google.com/sdk/gcloud/reference/dns/managed-zones/delete), and
  [Azure DNS](https://learn.microsoft.com/cli/azure/network/dns/zone#az-network-dns-zone-delete).
- CDN and gateways: [AWS CloudFront](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/delete-distribution.html),
  [Google Cloud API Gateway](https://cloud.google.com/sdk/gcloud/reference/api-gateway/gateways/delete), and
  [Azure API Management](https://learn.microsoft.com/cli/azure/apim#az-apim-delete).
- Traffic and monitoring: [AWS load balancing](https://docs.aws.amazon.com/cli/latest/reference/elbv2/delete-load-balancer.html),
  [Google Cloud forwarding rules](https://cloud.google.com/sdk/gcloud/reference/compute/forwarding-rules/delete),
  [Google Cloud monitoring policies](https://cloud.google.com/sdk/gcloud/reference/monitoring/policies/delete), and
  [Azure metric alerts](https://learn.microsoft.com/cli/azure/monitor/metrics/alert#az-monitor-metrics-alert-delete).
- Email: [AWS SES identities](https://docs.aws.amazon.com/cli/latest/reference/sesv2/delete-email-identity.html) and
  [contact lists](https://docs.aws.amazon.com/cli/latest/reference/sesv2/delete-contact-list.html).
- Feature flags: [LaunchDarkly CLI](https://github.com/launchdarkly/ldcli) and
  [feature-flag deletion](https://launchdarkly.com/docs/api/feature-flags/delete-feature-flag).
- Payments: [Stripe CLI](https://docs.stripe.com/stripe-cli/use-cli),
  [product deletion](https://docs.stripe.com/api/products/delete), and
  [webhook endpoint deletion](https://docs.stripe.com/api/webhook_endpoints/delete).
