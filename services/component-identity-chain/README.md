# identity-chain signed component

This is a runnable, synthetic IDOR training component for the `signed-node-handler-v1` ABI. It demonstrates the curated component supply chain without claiming a CVE: all records are synthetic and the only exposed finding is `scenario-idor` / CWE-639.

Build the helper as an OCI layer from the repository root, push it, sign its digest, and register only the server-owned coordinates:

```json
{
  "identity-chain@1.0.0": {
    "imageRef": "registry.example/codegate/components/identity-chain@sha256:<digest>",
    "sourcePath": "/opt/codegate/package/",
    "destination": "/opt/codegate/packages/identity-chain/",
    "runtimeKind": "signed-node-handler-v1"
  }
}
```

AI receives only `identity-chain@1.0.0`; it never receives or chooses the image, paths, handler hash, or command.
