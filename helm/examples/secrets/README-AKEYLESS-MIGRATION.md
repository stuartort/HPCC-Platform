# Migration from Hashicorp Vault to AKeyless

This document describes the changes made to migrate HPCC Platform from Hashicorp Vault to AKeyless for secrets management.

## Overview

The HPCC Platform has been updated to use AKeyless instead of Hashicorp Vault for secrets management. AKeyless provides a unified secrets management platform with a simpler API interface and enhanced security features.

## Key Changes

### 1. API Endpoints

**Hashicorp Vault:**
- Authentication: Multiple endpoints per auth method
  - `/v1/auth/kubernetes/login`
  - `/v1/auth/approle/login`
  - `/v1/auth/cert/login`
- Secret Retrieval: GET `/v1/secret/data/{path}`

**AKeyless:**
- Authentication: Unified endpoint
  - `POST /auth` (for all authentication methods)
- Secret Retrieval: `POST /get-secret-value`

### 2. Authentication Methods

| Vault Method | AKeyless Method | Configuration Changes |
|--------------|-----------------|----------------------|
| AppRole (role_id + secret_id) | API Key Auth (access-id + access-key) | `@appRoleId` → `@accessId`, `@appRoleSecret` → `@accessKeySecret` |
| Kubernetes JWT | Kubernetes Auth | `@role` → `@accessId` |
| Client Certificate | Certificate Auth | `@role` → `@accessId` |
| Token | Pre-provisioned Token | No change to `@client-secret` |

### 3. Configuration Updates

**Old Vault Configuration:**
```xml
<vaults>
  <ecl name="ecl_vault" 
       url="https://vault.example.com:8200" 
       kind="kv_v2"
       appRoleId="my-role-id"
       appRoleSecret="appRoleSecret" />
</vaults>
```

**New AKeyless Configuration:**
```xml
<vaults>
  <ecl name="ecl_akeyless" 
       url="https://api.akeyless.io" 
       accessId="p-xxxxxx"
       accessKeySecret="accessKeySecret"
       namespace="/hpcc/ecl" />
</vaults>
```

### 4. Key Configuration Parameters

| Parameter | Vault Value | AKeyless Value | Notes |
|-----------|-------------|----------------|-------|
| `@url` | Vault server URL | AKeyless gateway URL | e.g., `https://api.akeyless.io` |
| `@kind` | `kv_v1` or `kv_v2` | Not needed | AKeyless uses unified API |
| `@namespace` | Vault namespace | Optional path prefix | Used as part of secret path |
| `@appRoleId` | Role ID | → `@accessId` | Access ID for authentication |
| `@appRoleSecret` | Secret name | → `@accessKeySecret` | K8s secret containing access key |
| `@role` | Role name (k8s/cert) | → `@accessId` | Access ID for k8s/cert auth |

### 5. Response Format Changes

**Vault KV v2 Response:**
```json
{
  "data": {
    "data": {
      "key1": "value1",
      "key2": "value2"
    }
  }
}
```

**AKeyless Response:**
```json
{
  "/path/to/secret": {
    "key1": "value1",
    "key2": "value2"
  }
}
```

### 6. Header Changes

- **Vault:** `X-Vault-Token: <token>`
- **AKeyless:** `Authorization: Bearer <token>`

## Migration Steps

### For API Key Authentication (replaces AppRole)

1. Create AKeyless access role with required permissions
2. Generate access-id and access-key
3. Store access-key in Kubernetes secret:
   ```bash
   kubectl create secret generic accessKeySecret \
     --from-literal=access-key='<your-access-key>'
   ```
4. Update HPCC configuration:
   ```yaml
   vaults:
     - name: ecl_akeyless
       url: https://api.akeyless.io
       accessId: p-xxxxxx
       accessKeySecret: accessKeySecret
   ```

### For Kubernetes Authentication

1. Configure AKeyless Kubernetes auth method
2. Create access role for your k8s service account
3. Update HPCC configuration:
   ```yaml
   vaults:
     - name: ecl_akeyless
       url: https://api.akeyless.io
       accessId: p-xxxxxx  # Your k8s auth access ID
   ```

### For Certificate Authentication

1. Configure AKeyless certificate auth method
2. Create access role with certificate
3. Place certificates in `/var/run/secrets/certificates/akeylessclient/<category>/`
   - `tls.crt` - Client certificate
   - `tls.key` - Client private key
4. Update HPCC configuration:
   ```yaml
   vaults:
     - name: ecl_akeyless
       url: https://api.akeyless.io
       accessId: p-xxxxxx
       useTLSCertificateAuth: true
   ```

## Backwards Compatibility

The implementation maintains the same interface (`IVaultManager`) used by HPCC Platform, ensuring:
- No changes required to application code
- Existing secret retrieval calls work unchanged
- Kubernetes secrets (local) continue to work as fallback

## Secret Path Format

AKeyless expects secrets in a path format:
- Example: `/hpcc/ecl/mysecret`
- Configure `@namespace` attribute to set path prefix
- Secret names are appended to the namespace path

## Testing Your Migration

1. Verify AKeyless connection:
   - Check HPCC logs for successful authentication
   - Look for "AKEYLESS TOKEN" messages

2. Test secret retrieval:
   - Use existing ECL code that accesses secrets
   - Verify secrets are retrieved correctly

3. Monitor for errors:
   - Authentication failures
   - Permission denied errors
   - Secret not found errors

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify access-id is correct
   - Check access-key secret exists and contains valid key
   - Ensure AKeyless access role has correct permissions

2. **Secret Not Found**
   - Verify secret path matches AKeyless configuration
   - Check namespace configuration
   - Ensure secret exists in AKeyless

3. **Permission Denied**
   - Review AKeyless access policy
   - Verify role has read permissions for secret path
   - Check authentication token is valid

## Additional Resources

- [AKeyless Documentation](https://docs.akeyless.io/)
- [AKeyless REST API](https://docs.akeyless.io/reference/)
- HPCC Platform secrets documentation

## Support

For issues or questions about the migration, please:
1. Check HPCC Platform logs for detailed error messages
2. Verify AKeyless configuration and permissions
3. Contact HPCC Systems support
