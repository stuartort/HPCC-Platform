# Using AKeyless Secrets with Kubernetes Authentication

This guide explains how to configure HPCC Platform to retrieve secrets from AKeyless using Kubernetes authentication.

## Prerequisites

- AKeyless account and gateway
- Kubernetes cluster with HPCC Platform deployed
- AKeyless Kubernetes authentication method configured
- Service account with appropriate permissions

## Overview

AKeyless supports Kubernetes authentication by validating the JWT token from the Kubernetes service account. This provides secure, automated authentication without managing credentials.

## Configuration Steps

### 1. Configure AKeyless Kubernetes Auth Method

In AKeyless, set up Kubernetes authentication:

```bash
# Configure Kubernetes auth in AKeyless
akeyless config-auth-method \
  --name k8s-auth \
  --type k8s \
  --k8s-host https://kubernetes.default.svc.cluster.local \
  --k8s-ca-cert "$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)"
```

### 2. Create AKeyless Access Role

Create an access role that will be used by your HPCC pods:

```bash
# Create access role
akeyless create-role \
  --name hpcc-ecl-access \
  --auth-method k8s-auth

# Associate with service account
akeyless assoc-role-auth-method \
  --role-name hpcc-ecl-access \
  --sub-claims serviceaccount_name=hpcc-service \
  --sub-claims namespace=hpcc

# Set permissions
akeyless set-role-rule \
  --role-name hpcc-ecl-access \
  --path /hpcc/ecl/* \
  --permission read
```

### 3. Get the Access ID

Retrieve the access ID for your role:

```bash
akeyless get-role --name hpcc-ecl-access
```

Note the access ID (e.g., `p-xxxxxxxxxxxx`).

### 4. Configure HPCC Platform

Update your HPCC values.yaml:

```yaml
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io  # Or your AKeyless gateway URL
    accessId: p-xxxxxxxxxxxx       # From step 3
    namespace: /hpcc/ecl           # Optional path prefix
```

### 5. Create Secrets in AKeyless

Create secrets that HPCC will access:

```bash
# Static secret
akeyless create-secret \
  --name /hpcc/ecl/database-credentials \
  --value '{"username":"dbuser","password":"dbpass"}'

# Dynamic secret example (for databases)
akeyless create-dynamic-secret \
  --name /hpcc/ecl/mysql-creds \
  --type mysql \
  --mysql-host mysql.example.com \
  --mysql-port 3306 \
  --mysql-dbname mydb
```

### 6. Access Secrets from ECL

In your ECL code:

```ecl
// Access static secret
dbCreds := getSecret('ecl', 'database-credentials');
username := dbCreds.username;
password := dbCreds.password;

// Use in HTTP call
httpResult := HTTPCALL(
    'https://api.example.com/data',
    'GET',
    HTTPHEADER('Authorization', 'Bearer ' + getSecret('ecl', 'api-token').token)
);
```

## Complete Example Configuration

### HPCC values.yaml

```yaml
# AKeyless configuration
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io
    accessId: p-abc123xyz
    namespace: /hpcc/ecl
    # Optional: connection tuning
    retries: 3
    retryWait: 1000
    connectTimeout: 5000
    readTimeout: 10000

# Ensure service account has proper roles
serviceAccount:
  create: true
  name: hpcc-service
```

## Authentication Flow

1. HPCC pod starts and reads Kubernetes service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`

2. When accessing a secret, HPCC sends authentication request:
   ```
   POST https://api.akeyless.io/auth
   {
     "access-id": "p-abc123xyz",
     "access-type": "k8s",
     "k8s_service_account_token": "<JWT token>"
   }
   ```

3. AKeyless validates the token with Kubernetes API server

4. AKeyless returns an access token

5. HPCC uses the access token to retrieve secrets:
   ```
   POST https://api.akeyless.io/get-secret-value
   Authorization: Bearer <access-token>
   {
     "names": ["/hpcc/ecl/database-credentials"]
   }
   ```

## Security Considerations

### Service Account Permissions

Ensure your service account has minimal permissions:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hpcc-service
  namespace: hpcc
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hpcc-role
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: hpcc-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: hpcc-role
subjects:
- kind: ServiceAccount
  name: hpcc-service
```

### AKeyless Access Policies

Apply least privilege in AKeyless:

```bash
# Restrict access by path
akeyless set-role-rule \
  --role-name hpcc-ecl-access \
  --path /hpcc/ecl/* \
  --permission read

# Restrict by namespace
akeyless assoc-role-auth-method \
  --role-name hpcc-ecl-access \
  --sub-claims namespace=hpcc
```

### Network Policies

Restrict network access to AKeyless:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: akeyless-access
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

### Check Authentication

View HPCC logs:

```bash
kubectl logs -l app=hpcc | grep -i akeyless
```

Look for:
- `"using kubernetes AKeyless auth"` - Authentication method selected
- `"AKEYLESS TOKEN ttl=xxx"` - Successful authentication
- Authentication errors

### Common Issues

1. **"missing k8s auth token"**
   - Service account token not mounted
   - Check `/var/run/secrets/kubernetes.io/serviceaccount/token` exists

2. **"token permission denied"**
   - Access ID incorrect
   - Role not associated with correct service account
   - Check AKeyless role configuration

3. **"secret not found"**
   - Secret path incorrect
   - Namespace prefix not matching
   - Verify secret exists in AKeyless

### Verify Configuration

```bash
# Check service account
kubectl get sa hpcc-service -n hpcc

# Check HPCC configuration
kubectl get configmap hpcc-config -n hpcc -o yaml

# Test AKeyless access from pod
kubectl exec -it <hpcc-pod> -- sh
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Advanced Configuration

### Token Caching

HPCC automatically caches AKeyless tokens:
- Tokens are reused until expiration
- Automatic renewal before expiration
- Retry on permission denied

### Connection Tuning

```yaml
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io
    accessId: p-abc123xyz
    retries: 5              # Number of retries
    retryWait: 2000         # Wait between retries (ms)
    connectTimeout: 10000   # Connection timeout (ms)
    readTimeout: 30000      # Read timeout (ms)
    backoffTimeout: 60000   # Backoff on auth failure (ms)
```

### Multiple AKeyless Instances

Configure different instances per category:

```yaml
vaults:
  - category: ecl
    name: ecl-akeyless
    url: https://api.akeyless.io
    accessId: p-ecl-access
    
  - category: git
    name: git-akeyless
    url: https://api.akeyless.io
    accessId: p-git-access
    
  - category: eclUser
    name: user-akeyless
    url: https://api.akeyless.io
    accessId: p-user-access
```

## Migration from Vault

If migrating from Hashicorp Vault:

1. Keep existing Vault configuration during transition
2. Add AKeyless configuration
3. Migrate secrets from Vault to AKeyless
4. Test with AKeyless
5. Remove Vault configuration

See [README-AKEYLESS-MIGRATION.md](README-AKEYLESS-MIGRATION.md) for detailed migration guide.

## References

- [AKeyless Kubernetes Auth Documentation](https://docs.akeyless.io/docs/k8s-auth-method)
- [AKeyless REST API](https://docs.akeyless.io/reference)
- HPCC Platform Secrets Documentation
