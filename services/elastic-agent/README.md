# ZeroTOP Elastic collector adapter

This image is the constrained local-development implementation of the
`elastic_agent` runtime role. It tails the scenario NDJSON volume, performs
idempotent, bounded 500-document bulk indexing into the run-scoped Elasticsearch
service, and creates the matching Kibana data view so Discover is immediately
usable. A run may contain up to 5,000 ECS documents.

Production deployments should bind the same role to a digest-pinned Elastic
Agent golden image and a run-scoped Fleet policy. Keeping the image outside the
AI-generated specification prevents prompts from selecting collector binaries
or credentials.
