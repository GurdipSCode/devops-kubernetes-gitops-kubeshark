# devops-kubernetes-gitops-kubeshark

Comprehensive OPA (Open Policy Agent) policies to secure and govern Kubeshark deployments in Kubernetes clusters.

## 🎯 Overview

Kubeshark is a powerful API traffic analyzer for Kubernetes that captures and analyzes network traffic between pods and services. While extremely useful for debugging and observability, it can pose security and compliance risks if not properly configured.

These OPA policies ensure that Kubeshark:
- ✅ Never captures traffic from sensitive namespaces (kube-system, vault, secrets)
- ✅ Redacts sensitive data (passwords, API keys, credit cards, PII)
- ✅ Has appropriate resource limits to prevent cluster impact
- ✅ Has proper RBAC configuration (least privilege)
- ✅ Implements data retention policies
- ✅ Complies with security standards (PCI, HIPAA, GDPR)

---

## 📦 Policies Included

### 1. **Namespace Restrictions** (`namespace_restrictions.rego`)
**Severity:** HIGH

Prevents Kubeshark from capturing traffic from restricted and sensitive namespaces.

**What it checks:**
- ❌ DENY: Capturing kube-system, vault, cert-manager, sealed-secrets
- ⚠️ WARN: Capturing production/finance namespaces without approval
- ✅ REQUIRE: Namespace filtering configured on DaemonSets

**Example violation:**
```yaml
# ❌ DENIED
kind: ConfigMap
metadata:
  name: kubeshark-config
data:
  namespaces: "default,kube-system,production"  # ← kube-system is restricted!
```

---

### 2. **Data Filtering** (`data_filtering.rego`)
**Severity:** CRITICAL

Ensures Kubeshark redacts sensitive data to prevent credential exposure.

**What it checks:**
- ❌ CRITICAL: Authorization headers must be redacted
- ❌ CRITICAL: Cookie/Set-Cookie must be redacted
- ❌ CRITICAL: API keys in query params must be redacted
- ❌ CRITICAL: Passwords in JSON bodies must be redacted
- ❌ CRITICAL: Kubernetes /api/v1/secrets must be excluded
- ⚠️ WARN: Credit card patterns (PCI compliance)
- ⚠️ WARN: SSN patterns (HIPAA compliance)
- ⚠️ WARN: Email addresses (GDPR compliance)

**Example violation:**
```yaml
# ❌ CRITICAL
kind: ConfigMap
metadata:
  name: kubeshark-config
data:
  namespaces: "default"
  # Missing header redaction configuration!
```

**Required configuration:**
```yaml
# ✅ GOOD
kind: ConfigMap
metadata:
  name: kubeshark-config
data:
  redacted-headers: "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token"
  redacted-query-params: "password,token,secret,api_key,apikey,access_token"
  redacted-json-fields: "password,token,secret,apiKey,creditCard,ssn"
  excluded-paths: "/api/v1/secrets"
  redact-credit-cards: "true"  # PCI compliance
  redact-ssn: "true"            # HIPAA compliance
```

---

### 3. **Resource Limits** (`resource_limits.rego`)
**Severity:** HIGH

Ensures Kubeshark has appropriate resource limits and retention policies.

**What it checks:**
- ❌ CRITICAL: Memory and CPU limits must be set
- ❌ CRITICAL: Retention period must be ≤ 24 hours
- ❌ CRITICAL: Capture size must be ≤ 500MB
- ⚠️ WARN: Memory limit > 2Gi (excessive)
- ⚠️ WARN: DaemonSet on all nodes (expensive)

**Example violation:**
```yaml
# ❌ DENIED
kind: DaemonSet
metadata:
  name: kubeshark-worker
spec:
  template:
    spec:
      containers:
      - name: kubeshark
        image: kubeshark/kubeshark:latest
        # Missing resource limits!
```

**Required configuration:**
```yaml
# ✅ GOOD
kind: DaemonSet
spec:
  template:
    spec:
      nodeSelector:
        node-role.kubernetes.io/worker: "true"  # Don't run on control plane
      containers:
      - name: kubeshark
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 256Mi
---
kind: ConfigMap
metadata:
  name: kubeshark-config
data:
  retention-hours: "12"        # Max 24 hours
  max-capture-size-mb: "200"   # Max 500MB
```

---

### 4. **RBAC Validation** (`rbac.rego`)
**Severity:** HIGH

Ensures Kubeshark has minimal required permissions (least privilege).

**What it checks:**
- ❌ CRITICAL: Cannot access Kubernetes secrets
- ❌ CRITICAL: Cannot have wildcard permissions (* resources or verbs)
- ❌ CRITICAL: Cannot be bound to cluster-admin
- ❌ CRITICAL: Cannot escalate RBAC privileges
- ⚠️ WARN: Should not modify ConfigMaps (read-only preferred)
- ⚠️ WARN: Dashboard SA should set automountServiceAccountToken=false

**Example violation:**
```yaml
# ❌ CRITICAL
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubeshark-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services", "secrets"]  # ← secrets access!
  verbs: ["get", "list", "watch"]
```

**Required configuration:**
```yaml
# ✅ GOOD
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubeshark-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]  # NO secrets!
  verbs: ["get", "list", "watch"]                # Read-only
```

---

## 🚀 Installation

### Prerequisites
- Kubernetes cluster
- OPA Gatekeeper installed
- Kubeshark (to be secured)

### Install Gatekeeper (if not already installed)
```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml
```

### Install Kubeshark Policies

#### Option 1: Using provided script
```bash
cd kubeshark-policies
./scripts/install.sh
```

#### Option 2: Manual installation
```bash
# Create ConstraintTemplates
kubectl apply -f gatekeeper/templates/

# Create Constraints
kubectl apply -f gatekeeper/constraints/

# Verify installation
kubectl get constrainttemplates | grep kubeshark
kubectl get constraints | grep kubeshark
```

---

## 🧪 Testing

### Run OPA Tests
```bash
# Run all tests
opa test . -v

# Test specific policy
opa test namespace_restrictions.rego namespace_restrictions_test.rego -v

# Check test coverage
opa test . --coverage
```

### Test Against Sample Manifests
```bash
# Test with good configuration
opa eval -d . -i examples/good/kubeshark-config.yaml \
  "data.kubernetes.admission.kubeshark.data_filtering.deny"

# Test with bad configuration (should have violations)
opa eval -d . -i examples/bad/kubeshark-no-redaction.yaml \
  "data.kubernetes.admission.kubeshark.data_filtering.deny"
```

---

## 📊 Policy Decision Matrix

| Resource | Namespace Restrictions | Data Filtering | Resource Limits | RBAC |
|----------|----------------------|----------------|-----------------|------|
| ConfigMap | ✅ Check namespaces | ✅ Check redaction | ✅ Check retention | - |
| DaemonSet | ✅ Check NS filter | - | ✅ Check limits | - |
| Deployment | ✅ Check NS filter | - | ✅ Check limits | - |
| ClusterRole | - | - | - | ✅ Check permissions |
| Role | - | - | - | ✅ Check permissions |
| ServiceAccount | - | - | - | ✅ Check automount |

---

## 🎯 Use Cases

### Use Case 1: Prevent Secrets Exposure
**Problem:** Kubeshark captures all traffic, including Authorization headers with bearer tokens.

**Solution:** `data_filtering.rego` forces redaction of:
- Authorization headers
- Cookie/Set-Cookie
- X-API-Key, X-Auth-Token
- password/token query parameters
- Passwords in request/response bodies

### Use Case 2: Compliance (PCI/HIPAA/GDPR)
**Problem:** Capturing credit cards, SSNs, or emails violates compliance requirements.

**Solution:** Policies enforce:
- Credit card pattern redaction (PCI DSS)
- SSN pattern redaction (HIPAA)
- Email address redaction (GDPR)
- Data retention limits (≤ 24 hours)

### Use Case 3: Prevent Cluster Disruption
**Problem:** Kubeshark without limits can consume excessive resources.

**Solution:** `resource_limits.rego` enforces:
- Memory limit: 256Mi - 2Gi
- CPU limit: 100m - 1000m
- Capture size: ≤ 500MB
- Retention: ≤ 24 hours

### Use Case 4: Least Privilege Access
**Problem:** Kubeshark with excessive RBAC can access secrets and modify cluster state.

**Solution:** `rbac.rego` prevents:
- Access to Kubernetes secrets
- Wildcard permissions
- Cluster-admin binding
- RBAC escalation

---

## 🔍 Examples

### Good Configuration

```yaml
# Namespace filtering
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubeshark-config
  labels:
    app.kubernetes.io/name: kubeshark
  annotations:
    kubeshark.io/sensitive-approved: "true"  # Required for production namespace
data:
  namespaces: "default,staging,production"
  
  # Data filtering (REQUIRED)
  redacted-headers: "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate"
  redacted-query-params: "password,token,secret,api_key,apikey,access_token,refresh_token,client_secret"
  redacted-json-fields: "password,token,secret,apiKey,accessToken,refreshToken,privateKey,clientSecret,creditCard,ssn,bankAccount"
  excluded-paths: "/api/v1/secrets,/api/v1/namespaces/*/secrets"
  
  # Compliance
  redact-credit-cards: "true"
  redact-ssn: "true"
  redact-emails: "true"
  
  # Retention
  retention-hours: "12"
  max-capture-size-mb: "200"

---
# DaemonSet with proper configuration
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kubeshark-worker
  labels:
    app.kubernetes.io/name: kubeshark
spec:
  selector:
    matchLabels:
      app: kubeshark
  template:
    spec:
      nodeSelector:
        node-role.kubernetes.io/worker: "true"  # Only worker nodes
      
      serviceAccountName: kubeshark-worker
      
      containers:
      - name: kubeshark
        image: kubeshark/kubeshark:latest
        args:
          - start
          - --namespaces
          - default,staging,production
        
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 256Mi

---
# RBAC with minimal permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubeshark-viewer
  labels:
    app.kubernetes.io/name: kubeshark
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets"]
  verbs: ["get", "list"]

---
# ServiceAccount with no auto-mount (for dashboard)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubeshark-dashboard
automountServiceAccountToken: false
```

---

## ⚠️ Common Issues

### Issue 1: Policy blocks legitimate Kubeshark deployment

**Symptom:**
```
Error: admission webhook denied the request: 
CRITICAL: Kubeshark must have header redaction configured
```

**Solution:** Add required redaction configuration to ConfigMap

### Issue 2: Warning about production namespace

**Symptom:**
```
WARNING: Kubeshark capturing sensitive namespace 'production' 
requires approval annotation
```

**Solution:** Add approval annotation:
```yaml
metadata:
  annotations:
    kubeshark.io/sensitive-approved: "true"
```

### Issue 3: Resource limit warnings

**Symptom:**
```
WARNING: Kubeshark memory limit '4Gi' exceeds recommended maximum '2Gi'
```

**Solution:** Reduce memory limit to 2Gi or less

---

## 📚 References

- [Kubeshark Documentation](https://docs.kubeshark.co/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [OPA Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

---

## 🤝 Contributing

To add new policies:
1. Create policy file: `my_policy.rego`
2. Add METADATA block
3. Create tests: `my_policy_test.rego`
4. Run tests: `opa test .`
5. Generate ConstraintTemplate
6. Update documentation

---

## 📄 License

MIT License - see LICENSE file for details.
