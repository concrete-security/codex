# RA-TLS Integration for Codex

This document describes how to use Remote Attestation TLS (RA-TLS) with Codex to connect to LLM providers running in Trusted Execution Environments (TEEs).

## Overview

RA-TLS enables Codex to verify that the model provider is running inside a genuine TEE (such as Intel TDX) before sending any data. This provides cryptographic assurance that your prompts and responses are processed in a secure, isolated environment.

## Building with RA-TLS Support

RA-TLS support is an optional feature. To build Codex with RA-TLS:

```bash
cd codex-rs
cargo build --release -p codex-cli --features ratls
```

Or install directly:

```bash
cargo install --path cli --features ratls
```

## Configuration

### Enabling RA-TLS for a Provider

Add a provider with `use_ratls = true` in your `~/.codex/config.toml`:

```toml
[model_providers.vllm-tee]
name = "vLLM TEE"
base_url = "https://vllm.example.com/v1"
wire_api = "chat"
use_ratls = true

[model_providers.vllm-tee.ratls_policy]
tee_type = "Tdx"
allowed_tdx_status = ["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded"]
pccs_url = "https://pccs.phala.network/tdx/certification/v4"
```

### Using the Provider

Set the provider in your config or profile:

```toml
model_provider = "vllm-tee"
model = "your-model-name"
```

## Policy Configuration

The `ratls_policy` section controls attestation verification:

| Field | Description | Default |
|-------|-------------|---------|
| `tee_type` | TEE type: `"Tdx"` (Intel TDX) | `"Tdx"` |
| `allowed_tdx_status` | Acceptable TCB status values | `["UpToDate"]` |
| `pccs_url` | Intel PCCS collateral service URL | Phala Network |
| `min_tdx_tcb` | Optional minimum TCB requirements | None |

### TCB Status Values

Common status values you may want to allow:

- `"UpToDate"` - Platform is fully up to date
- `"SWHardeningNeeded"` - Software mitigations available
- `"ConfigurationNeeded"` - Configuration changes recommended
- `"OutOfDate"` - Platform needs updates (use with caution)

### Example: Strict Policy

For production environments with strict security requirements:

```toml
[model_providers.secure-llm.ratls_policy]
tee_type = "Tdx"
allowed_tdx_status = ["UpToDate"]
```

### Example: Development Policy

For development/testing where TEE status may vary:

```toml
[model_providers.dev-llm.ratls_policy]
tee_type = "Tdx"
allowed_tdx_status = [
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "OutOfDateConfigurationNeeded"
]
```

## How It Works

1. **TLS Handshake**: Codex establishes a TLS 1.3 connection with CA certificate verification
2. **Quote Request**: After TLS, Codex requests an attestation quote from the server
3. **Quote Verification**: The quote is verified using Intel DCAP:
   - Signature validation against Intel's certificates
   - TCB status check against your policy
   - Freshness verification using a random nonce
   - TLS key binding verification
4. **Secure Communication**: If verification passes, API requests proceed over the attested connection

## Troubleshooting

### "Attestation verification failed: TEE not trusted"

The server's attestation quote didn't meet your policy. Check:
- Is the server actually running in a TEE?
- Are your `allowed_tdx_status` values appropriate?
- Is the PCCS URL reachable?

### Connection timeouts

RA-TLS adds an extra round-trip for attestation. The first connection may be slower than regular HTTPS.

### Feature not available

If you see errors about missing RA-TLS types, ensure you built with `--features ratls`.

## Security Considerations

- **Verify provider identity**: RA-TLS verifies the TEE, but you should also verify you're connecting to the intended provider (check the domain/certificate)
- **TCB status**: Stricter policies are more secure but may reject legitimate servers that haven't updated
- **Network security**: RA-TLS protects the connection to the TEE; ensure your network path to the server is also secure

## Architecture

```
┌─────────────┐     TLS + Attestation     ┌─────────────────┐
│   Codex     │ ◄─────────────────────────► │  TEE Server     │
│   Client    │                            │  (Intel TDX)    │
└─────────────┘                            └─────────────────┘
       │                                          │
       │ 1. TLS Handshake                         │
       │ 2. Request /tdx_quote                    │
       │ 3. Verify quote + policy                 │
       │ 4. API requests over attested TLS        │
       └──────────────────────────────────────────┘
```

## Related Documentation

- [ratls-core library](../../ratls/README.md) - The underlying RA-TLS implementation
- [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) - Intel Trust Domain Extensions
