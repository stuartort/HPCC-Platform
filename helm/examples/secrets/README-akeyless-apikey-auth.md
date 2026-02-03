# Using AKeyless Secrets with API Key Authentication

This guide explains how to configure HPCC Platform to retrieve secrets from AKeyless using API Key authentication (equivalent to Vault's AppRole authentication).

## Prerequisites

- AKeyless account and gateway
- Kubernetes cluster with HPCC Platform deployed
- AKeyless access credentials (access-id and access-key)

## Overview

API Key authentication is the most common authentication method for AKeyless. It uses an access-id (public identifier) and an access-key (secret credential) to authenticate. This is equivalent to Vault's AppRole authentication which used role_id and secret_id.

## Configuration Steps

### 1. Create AKeyless Access Role

In AKeyless, create an access role with appropriate permissions:

```bash
# Create access role
akeyless create-role \
  --name hpcc-ecl-role \
  --description "HPCC ECL access role"

# Create auth method for API key
akeyless create-auth-method \
  --name api-key-auth \
  --type api_key

# Associate role with auth method
akeyless assoc-role-auth-method \
  --role-name hpcc-ecl-role \
  --auth-method api-key-auth
```

### 2. Generate Access Credentials

Generate access-id and access-key:

```bash
# Create access key
akeyless create-auth-method-api-key \
  --name hpcc-ecl-access \
  --role-name hpcc-ecl-role

# Get the credentials
akeyless get-auth-method \
  --name hpcc-ecl-access
```

This will provide:
- **Access ID**: e.g., `p-abc123xyz456`
- **Access Key**: e.g., `aBcDeFgHiJkLmNoPqRsTuVwXyZ123456`

### 3. Store Access Key in Kubernetes Secret

Store the access-key in a Kubernetes secret:

```bash
kubectl create secret generic accessKeySecret \
  --from-literal=access-key='aBcDeFgHiJkLmNoPqRsTuVwXyZ123456' \
  --namespace=hpcc
```

Or using a YAML file:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: accessKeySecret
  namespace: hpcc
type: Opaque
stringData:
  access-key: aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
```

Apply with:
```bash
kubectl apply -f accessKeySecret.yaml
```

### 4. Set Permissions in AKeyless

Configure what secrets the role can access:

```bash
# Allow read access to specific path
akeyless set-role-rule \
  --role-name hpcc-ecl-role \
  --path /hpcc/ecl/* \
  --permission read

# Can set multiple rules
akeyless set-role-rule \
  --role-name hpcc-ecl-role \
  --path /hpcc/common/* \
  --permission read
```

### 5. Configure HPCC Platform

Update your HPCC values.yaml:

```yaml
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io  # Or your AKeyless gateway URL
    accessId: p-abc123xyz456       # From step 2
    accessKeySecret: accessKeySecret  # Name of k8s secret from step 3
    namespace: /hpcc/ecl           # Optional path prefix
```

### 6. Create Secrets in AKeyless

Create the secrets that HPCC will access:

```bash
# Simple static secret
akeyless create-secret \
  --name /hpcc/ecl/api-token \
  --value "my-secret-api-token"

# JSON secret with multiple fields
akeyless create-secret \
  --name /hpcc/ecl/database-config \
  --value '{"host":"db.example.com","port":"3306","username":"dbuser","password":"dbpass"}'

# Multiline secret (certificates, keys)
akeyless create-secret \
  --name /hpcc/ecl/ssl-cert \
  --value "$(cat certificate.pem)"
```

## Complete Example Configuration

### values.yaml

```yaml
# AKeyless API Key authentication configuration
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io
    accessId: p-abc123xyz456
    accessKeySecret: accessKeySecret
    namespace: /hpcc/ecl
    # Optional connection settings
    retries: 3
    retryWait: 1000
    connectTimeout: 5000
    readTimeout: 10000
    verify_server: true

  # Additional category example
  - category: git
    name: git-akeyless
    url: https://api.akeyless.io
    accessId: p-def789ghi012
    accessKeySecret: gitAccessKeySecret
    namespace: /hpcc/git
```

### Access Key Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: accessKeySecret
  namespace: hpcc
type: Opaque
stringData:
  access-key: aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
---
apiVersion: v1
kind: Secret
metadata:
  name: gitAccessKeySecret
  namespace: hpcc
type: Opaque
stringData:
  access-key: XyZ987wVuTsRqPoNmLkJiHgFeDcBa654
```

## Using Secrets in ECL Code

### Simple Secret Value

```ecl
// Get API token
token := getSecret('ecl', 'api-token').value;

// Use in HTTP call
response := HTTPCALL(
    'https://api.example.com/data',
    'GET',
    HTTPHEADER('Authorization', 'Bearer ' + token)
);
```

### JSON Secret with Multiple Fields

```ecl
// Get database configuration
dbConfig := getSecret('ecl', 'database-config');

// Access individual fields
dbHost := dbConfig.host;
dbPort := dbConfig.port;
dbUser := dbConfig.username;
dbPass := dbConfig.password;

// Use in database connection
result := DATABASE(
    dbHost + ':' + dbPort,
    dbUser,
    dbPass,
    'SELECT * FROM table'
);
```

### Dynamic Secret Names

```ecl
// Build secret name dynamically
environment := 'production';
secretName := 'api-key-' + environment;
apiKey := getSecret('ecl', secretName).value;
```

## Authentication Flow

1. On startup or when accessing a secret, HPCC loads the access-key from the Kubernetes secret

2. HPCC sends authentication request:
   ```
   POST https://api.akeyless.io/auth
   Content-Type: application/json
   
   {
     "access-id": "p-abc123xyz456",
     "access-key": "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
   }
   ```

3. AKeyless validates credentials and returns access token:
   ```json
   {
     "token": "t-xxxxxxxxxxxx",
     "ttl": 3600
   }
   ```

4. HPCC caches the token and uses it to retrieve secrets:
   ```
   POST https://api.akeyless.io/get-secret-value
   Authorization: Bearer t-xxxxxxxxxxxx
   Content-Type: application/json
   
   {
     "names": ["/hpcc/ecl/api-token"]
   }
   ```

5. Token is automatically renewed before expiration

## Security Best Practices

### Protect Access Keys

1. **Never commit access keys to source control**
2. **Use Kubernetes secrets** to store access keys
3. **Rotate keys regularly** using AKeyless key rotation
4. **Use different keys** for different environments (dev, staging, prod)

### Limit Permissions

Configure minimal required permissions:

```bash
# Read-only access to specific paths
akeyless set-role-rule \
  --role-name hpcc-ecl-role \
  --path /hpcc/ecl/* \
  --permission read

# No write, update, or delete permissions
```

### Audit Access

Enable auditing in AKeyless:

```bash
# View audit logs
akeyless get-event-logs \
  --start-date 2024-01-01 \
  --end-date 2024-01-31 \
  --auth-method hpcc-ecl-access
```

### Network Security

Restrict network access to AKeyless gateway:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: akeyless-access
  namespace: hpcc
spec:
  podSelector:
    matchLabels:
      app: hpcc
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 443
```

## Troubleshooting

### Check Configuration

View HPCC logs:

```bash
kubectl logs -l app=hpcc -n hpcc | grep -i akeyless
```

Look for:
- `"using AKeyless API key auth"` - Auth method selected
- `"AKEYLESS TOKEN ttl=xxx"` - Successful authentication
- Authentication errors

### Common Issues

1. **"access key secret not found"**
   - Kubernetes secret doesn't exist
   - Secret name doesn't match configuration
   ```bash
   kubectl get secret accessKeySecret -n hpcc
   ```

2. **"access key not found at 'accessKeySecret/access-key'"**
   - Secret exists but doesn't have `access-key` field
   - Check secret contents:
   ```bash
   kubectl get secret accessKeySecret -n hpcc -o yaml
   ```

3. **"token permission denied"**
   - Access ID or key incorrect
   - Role permissions insufficient
   - Verify in AKeyless:
   ```bash
   akeyless get-auth-method --name hpcc-ecl-access
   akeyless get-role --name hpcc-ecl-role
   ```

4. **"secret not found"**
   - Secret path incorrect
   - Namespace prefix not matching
   - Secret doesn't exist in AKeyless
   ```bash
   akeyless get-secret-value --name /hpcc/ecl/api-token
   ```

### Verify Setup

```bash
# Check K8s secret exists
kubectl get secret accessKeySecret -n hpcc

# View secret (base64 encoded)
kubectl get secret accessKeySecret -n hpcc -o jsonpath='{.data.access-key}' | base64 -d

# Check HPCC configuration
kubectl get configmap hpcc-config -n hpcc -o yaml | grep -A 10 vaults

# Test from HPCC pod
kubectl exec -it <hpcc-pod> -n hpcc -- sh
# Then manually test AKeyless connection if needed
```

## Rotating Access Keys

Regular key rotation improves security:

### 1. Create New Access Key

```bash
akeyless create-auth-method-api-key \
  --name hpcc-ecl-access-v2 \
  --role-name hpcc-ecl-role
```

### 2. Update Kubernetes Secret

```bash
kubectl create secret generic accessKeySecret-new \
  --from-literal=access-key='<new-access-key>' \
  --namespace=hpcc
```

### 3. Update HPCC Configuration

```yaml
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io
    accessId: p-newaccessid  # New access ID
    accessKeySecret: accessKeySecret-new  # New secret name
```

### 4. Deploy Changes

```bash
helm upgrade hpcc ./hpcc -n hpcc -f values.yaml
```

### 5. Delete Old Access Key

After verifying the new key works:

```bash
akeyless delete-auth-method --name hpcc-ecl-access
kubectl delete secret accessKeySecret -n hpcc
```

## Advanced Configuration

### Custom AKeyless Gateway

If using a self-hosted AKeyless gateway:

```yaml
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://akeyless.mycompany.com
    accessId: p-abc123xyz456
    accessKeySecret: accessKeySecret
    verify_server: true  # Set to false for self-signed certs
```

### Multiple Environments

Configure different keys per environment:

```yaml
# Production
vaults:
  - category: ecl
    name: ecl-akeyless-prod
    url: https://api.akeyless.io
    accessId: p-prod-id
    accessKeySecret: prodAccessKeySecret
    namespace: /hpcc/prod/ecl

# Staging
  - category: ecl
    name: ecl-akeyless-staging
    url: https://api.akeyless.io
    accessId: p-staging-id
    accessKeySecret: stagingAccessKeySecret
    namespace: /hpcc/staging/ecl
```

## Migration from Vault AppRole

If migrating from Vault AppRole authentication:

### Old Vault Configuration
```yaml
vaults:
  - category: ecl
    url: https://vault.example.com
    appRoleId: role-id-value
    appRoleSecret: vaultAppRoleSecret
```

### New AKeyless Configuration
```yaml
vaults:
  - category: ecl
    url: https://api.akeyless.io
    accessId: p-abc123xyz456
    accessKeySecret: accessKeySecret
```

### Migration Steps
1. Create AKeyless access role and generate credentials
2. Store access-key in Kubernetes secret
3. Add AKeyless configuration alongside Vault
4. Migrate secrets from Vault to AKeyless
5. Test with AKeyless
6. Remove Vault configuration

See [README-AKEYLESS-MIGRATION.md](README-AKEYLESS-MIGRATION.md) for detailed guide.

## References

- [AKeyless API Key Auth Documentation](https://docs.akeyless.io/docs/api-key-auth)
- [AKeyless REST API Reference](https://docs.akeyless.io/reference)
- HPCC Platform Secrets Documentation
