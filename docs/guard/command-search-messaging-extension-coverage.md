# Search and Messaging Command Extension Coverage

Guard's search and messaging extensions match parsed executables, HTTP methods and service targets, leading options, exact subcommands, and deletion flags. Quoted examples and unrelated HTTP APIs do not trigger these rules.

## Covered Operations

- Explicit Elasticsearch DELETE requests to service-specific APIs or non-root port 9200 paths
- Kafka topic, consumer-group, offset, and record deletion
- RabbitMQ queue, user, virtual-host deletion, and broker reset
- NATS stream, consumer, key-value, and object-store removal or purge
- Portable executable names and Kafka shell and batch launchers
- RabbitMQ dry runs, help commands, version commands, and observer commands remain outside destructive review

## References

- [Elasticsearch delete index API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-indices-delete)
- [Kafka documentation](https://kafka.apache.org/documentation/)
- [RabbitMQ rabbitmqctl](https://www.rabbitmq.com/docs/man/rabbitmqctl.8)
- [NATS CLI](https://docs.nats.io/using-nats/nats-tools/nats_cli)
