# Security policy

## Supported versions

Only the latest tagged release receives security fixes while the project is in
alpha.

## Reporting

Do not open a public issue containing credentials, captured content, private
network details, or an exploitable trace. Contact the repository maintainers
through the private security-reporting channel configured by the hosting
organization.

## Deployment boundary

The collector has no application-level authentication or TLS termination. It
binds to loopback by default and must remain behind a trusted local network or
an authenticated ingress. It stores request and response bodies as sensitive
raw evidence. Common credential-bearing headers are removed during compatible
envelope normalization, but operators remain responsible for source consent,
field policy, encryption at rest, access control, retention, and deletion.
