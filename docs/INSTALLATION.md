# elf-owl Installation Guide

## Prerequisites

### System Requirements

elf-owl requires a Linux system with kernel-level eBPF support:

- **Linux Kernel**: 5.8+ (eBPF features required)
- **Architecture**: x86_64 or ARM64 (amd64/arm64)
- **Container Runtime**: Docker, containerd, or CRI-O
- **Kubernetes**: 1.19+ (if deploying in Kubernetes)

### eBPF Support Verification

Verify your kernel supports eBPF:

```bash
# Check kernel version
uname -r

# Should be 5.8 or higher. For older kernels, eBPF might be available
# but with limited features.

# Check eBPF support
cat /boot/config-$(uname -r) | grep CONFIG_BPF

# Output should include:
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_JIT=y
```

### Kubernetes Requirements

- **Kubernetes Version**: 1.19+
- **Cluster Access**: Admin or cluster-admin role required for installation
- **Nodes**: All nodes must meet the eBPF support requirements above
- **Network**: Cluster should have network connectivity to Owl SaaS platform (if using)

### API Credentials

To send events to the Owl platform, you need:
- **Cluster ID**: Unique identifier for your cluster
- **API Token**: Authentication token for the Owl platform
- **API Endpoint**: URL of the Owl SaaS platform

## Installation Methods

### Method 1: Helm Chart (Recommended)

#### Prerequisites
- Helm 3.0+
- kubectl configured with cluster access

#### Installation Steps

1. **Add the elf-owl Helm repository**:
   ```bash
   helm repo add elf-owl https://charts.elf-owl.io
   helm repo update
   ```

2. **Create namespace**:
   ```bash
   kubectl create namespace kube-system  # If not already created
   ```

3. **Create API credentials secret** (if using Owl platform):
   ```bash
   kubectl create secret generic elf-owl-api-token \
     --from-literal=api-token=YOUR_API_TOKEN \
     -n kube-system
   ```

4. **Create values file** (`elf-owl-values.yaml`):
   ```yaml
   # Global configuration
   global:
     clusterName: "prod-us-east-1"
     clusterID: "prod-us-east-1"

   # Agent configuration
   agent:
     enabled: true
     replicas: 1  # Usually 1 per node via DaemonSet

     # eBPF monitoring
     ebpf:
       enabled: true
       process:
         enabled: true
         buffer_size: 8192
         timeout: 5s
       network:
         enabled: true
         buffer_size: 8192
         timeout: 5s
       dns:
         enabled: true
         buffer_size: 8192
         timeout: 5s
       file:
         enabled: true
         buffer_size: 8192
         timeout: 5s
       capability:
         enabled: true
         buffer_size: 8192
         timeout: 5s

     # Logging configuration
     logging:
       level: "info"
       format: "json"

     # Owl SaaS platform integration
     owl_api:
       enabled: true
       endpoint: "https://api.owl-platform.com"
       auth:
         tokenSecretRef:
           name: "elf-owl-api-token"
           key: "api-token"

   # Resource requests/limits
   resources:
     requests:
       cpu: 100m
       memory: 128Mi
     limits:
       cpu: 500m
       memory: 512Mi

   # Pod security context
   podSecurityContext:
     runAsNonRoot: false
     capabilities:
       add:
         - SYS_RESOURCE
         - SYS_ADMIN

   # Node affinity (run on all nodes)
   affinity:
     nodeAffinity:
       requiredDuringSchedulingIgnoredDuringExecution:
         nodeSelectorTerms:
           - matchExpressions:
               - key: kubernetes.io/os
                 operator: In
                 values:
                   - linux
   ```

5. **Install the Helm chart**:
   ```bash
   helm install elf-owl elf-owl/elf-owl \
     -n kube-system \
     -f elf-owl-values.yaml
   ```

6. **Verify installation**:
   ```bash
   # Check if DaemonSet is created
   kubectl get daemonset -n kube-system elf-owl

   # Check pod status
   kubectl get pods -n kube-system -l app=elf-owl

   # Check logs
   kubectl logs -n kube-system -l app=elf-owl --tail=50
   ```

#### Upgrading the Helm Chart

```bash
# Update repository
helm repo update

# Upgrade installation
helm upgrade elf-owl elf-owl/elf-owl \
  -n kube-system \
  -f elf-owl-values.yaml

# Verify upgrade
kubectl rollout status daemonset/elf-owl -n kube-system
```

#### Uninstalling

```bash
helm uninstall elf-owl -n kube-system
```

### Method 2: kubectl apply (Manual)

#### Prerequisites
- kubectl configured with cluster access
- YAML manifest files available

#### Installation Steps

1. **Create namespace**:
   ```bash
   kubectl create namespace kube-system  # If not already created
   ```

2. **Create API credentials secret**:
   ```bash
   kubectl create secret generic elf-owl-api-token \
     --from-literal=api-token=YOUR_API_TOKEN \
     -n kube-system
   ```

3. **Create ConfigMap with configuration**:
   ```bash
   kubectl create configmap elf-owl-config \
     --from-file=config/elf-owl.yaml \
     -n kube-system
   ```

4. **Apply manifests** (in this order):
   ```bash
   # ClusterRole for RBAC
   kubectl apply -f k8s/clusterrole.yaml

   # ClusterRoleBinding
   kubectl apply -f k8s/clusterrolebinding.yaml

   # ServiceAccount
   kubectl apply -f k8s/serviceaccount.yaml

   # DaemonSet to deploy elf-owl on all nodes
   kubectl apply -f k8s/daemonset.yaml
   ```

5. **Verify installation**:
   ```bash
   kubectl get daemonset -n kube-system elf-owl
   kubectl get pods -n kube-system -l app=elf-owl
   kubectl logs -n kube-system -l app=elf-owl --tail=50
   ```

### Method 3: Docker (Standalone)

For standalone testing or non-Kubernetes deployments:

#### Prerequisites
- Docker installed
- Linux host with eBPF support
- Owl SaaS API credentials (if using)

#### Installation Steps

1. **Pull the image**:
   ```bash
   docker pull elf-owl:latest
   # Or build locally:
   # docker build -t elf-owl:latest .
   ```

2. **Create configuration file** (`elf-owl.yaml`):
   ```yaml
   agent:
     cluster_id: "standalone"
     node_name: $(hostname)

     ebpf:
       enabled: true
       process:
         enabled: true
       network:
         enabled: true
       dns:
         enabled: true
       file:
         enabled: true
       capability:
         enabled: true

     logging:
       level: "info"
       format: "json"
       output: "stdout"

     owl_api:
       enabled: true
       endpoint: "https://api.owl-platform.com"
       auth:
         token: "${OWL_API_TOKEN}"
   ```

3. **Run container**:
   ```bash
   docker run --privileged \
     --name elf-owl \
     -v /etc/elf-owl/config.yaml:/etc/elf-owl/config.yaml:ro \
     -e OWL_API_TOKEN=YOUR_API_TOKEN \
     -e LOG_LEVEL=info \
     elf-owl:latest
   ```

   Note: `--privileged` is required for eBPF syscalls

4. **View logs**:
   ```bash
   docker logs -f elf-owl
   ```

## Configuration

### Basic Configuration

The default configuration enables all monitors and sends events to Owl platform:

```yaml
agent:
  cluster_id: "prod-us-east-1"
  node_name: "worker-01"

  ebpf:
    enabled: true
    process:
      enabled: true
      buffer_size: 8192
      timeout: 5s
    network:
      enabled: true
      buffer_size: 8192
      timeout: 5s
    dns:
      enabled: true
      buffer_size: 8192
      timeout: 5s
    file:
      enabled: true
      buffer_size: 8192
      timeout: 5s
    capability:
      enabled: true
      buffer_size: 8192
      timeout: 5s

  logging:
    level: "info"
    format: "json"
    output: "stdout"

  owl_api:
    enabled: true
    endpoint: "https://api.owl-platform.com"
    auth:
      token: "${OWL_API_TOKEN}"
```

### Environment Variables

Configuration can also be controlled via environment variables:

```bash
# Logging
export LOG_LEVEL="info"           # debug, info, warn, error
export LOG_FORMAT="json"          # json or text

# eBPF Monitoring
export EBPF_ENABLED="true"
export PROCESS_MONITORING="true"
export NETWORK_MONITORING="true"
export DNS_MONITORING="true"
export FILE_MONITORING="true"
export CAPABILITY_MONITORING="true"

# Owl SaaS Platform
export OWL_API_ENABLED="true"
export OWL_API_ENDPOINT="https://api.owl-platform.com"
export OWL_API_TOKEN="your-api-token-here"
```

### Configuration Priority

Configuration is loaded in this order (later overrides earlier):

1. Built-in defaults
2. Configuration file (`elf-owl.yaml`)
3. Environment variables
4. ConfigMap (Kubernetes)

## Post-Installation Verification

### 1. Verify Pods are Running

```bash
kubectl get pods -n kube-system -l app=elf-owl -o wide

# Expected output:
# NAME                    READY   STATUS    RESTARTS   AGE   IP           NODE
# elf-owl-abc12           1/1     Running   0          5m    10.0.1.100   worker-01
# elf-owl-def45           1/1     Running   0          5m    10.0.1.101   worker-02
# elf-owl-ghi78           1/1     Running   0          5m    10.0.1.102   worker-03
```

### 2. Verify Logs are Being Generated

```bash
# Check logs from a specific pod
kubectl logs -n kube-system pod/elf-owl-abc12

# Watch logs in real-time
kubectl logs -n kube-system -l app=elf-owl -f

# Expected output includes:
# "process monitor initialized"
# "network monitor initialized"
# "dns monitor initialized"
# "file monitor initialized"
# "capability monitor initialized"
```

### 3. Verify Events are Captured

```bash
# Check for "push" log messages indicating events are being sent
kubectl logs -n kube-system -l app=elf-owl | grep "push"

# Expected output:
# "pushing 15 events to owl platform"
# "push succeeded"
```

### 4. Verify Owl Platform Connectivity

```bash
# Check if API communication is working
kubectl logs -n kube-system -l app=elf-owl | grep "owl_api"

# Expected output:
# "owl api client initialized"
# "successfully connected to owl platform"
```

### 5. Test with Known Processes

```bash
# Generate a test process that should be captured
kubectl exec -it pod/elf-owl-abc12 -n kube-system -- sh -c "echo 'test' > /tmp/test.txt"

# Check logs for file access event
kubectl logs -n kube-system pod/elf-owl-abc12 | grep "file_access"
```

## Troubleshooting

### Issue: Pods Not Starting

**Symptoms**: Pods stuck in pending or error state

**Solutions**:
```bash
# Check pod status and events
kubectl describe pod -n kube-system -l app=elf-owl

# Common reasons:
# 1. Insufficient resources
kubectl top nodes

# 2. Node selector mismatch
kubectl get nodes --show-labels

# 3. Check for init container failures
kubectl logs -n kube-system pod/elf-owl-abc12 --previous
```

### Issue: eBPF Load Failures

**Symptoms**: Error messages about eBPF programs not loading

**Solutions**:
```bash
# 1. Verify kernel has eBPF support
cat /boot/config-$(uname -r) | grep CONFIG_BPF

# 2. Check kernel version
uname -r
# Should be 5.8 or higher

# 3. Check dmesg for errors
dmesg | tail -20 | grep -i bpf
```

### Issue: No Events in Owl Platform

**Symptoms**: Pods running but no events appearing in Owl dashboard

**Solutions**:
```bash
# 1. Verify API token is correct
kubectl get secret -n kube-system elf-owl-api-token -o yaml

# 2. Check API connectivity
kubectl logs -n kube-system -l app=elf-owl | grep -i error | head -20

# 3. Verify cluster ID matches Owl platform configuration
kubectl get configmap -n kube-system elf-owl-config -o yaml | grep cluster_id

# 4. Check for network policy blocking outbound HTTPS
kubectl get networkpolicies -A | grep elf-owl
```

### Issue: High Memory/CPU Usage

**Symptoms**: Pods consuming significant resources

**Solutions**:
```yaml
# 1. Disable expensive monitors (file access)
# In values.yaml or ConfigMap:
agent:
  ebpf:
    file:
      enabled: false

# 2. Reduce buffer sizes
agent:
  ebpf:
    process:
      buffer_size: 4096  # Reduce from 8192
    network:
      buffer_size: 4096
    dns:
      buffer_size: 4096

# 3. Adjust resource limits in Helm values
resources:
  limits:
    cpu: 500m
    memory: 512Mi
```

### Issue: Permission Denied Errors

**Symptoms**: "Operation not permitted" errors in logs

**Solutions**:
```bash
# 1. Verify pod security context allows required capabilities
kubectl get daemonset -n kube-system elf-owl -o yaml | grep -A 10 securityContext

# 2. Check AppArmor or SELinux policies
sudo aa-status  # For AppArmor
getenforce      # For SELinux

# 3. Temporarily disable security to test
# In DaemonSet spec:
securityContext:
  privileged: true
```

### Issue: Network Connectivity

**Symptoms**: Cannot reach Owl platform

**Solutions**:
```bash
# 1. Test DNS resolution
kubectl exec -it pod/elf-owl-abc12 -n kube-system -- nslookup api.owl-platform.com

# 2. Test HTTPS connectivity
kubectl exec -it pod/elf-owl-abc12 -n kube-system -- curl -v https://api.owl-platform.com

# 3. Check network policies
kubectl get networkpolicies -A -o wide | grep elf-owl

# 4. Verify egress rules allow HTTPS (port 443)
kubectl describe networkpolicy -n kube-system elf-owl-egress
```

## Performance Tuning

### For High-Throughput Clusters

```yaml
agent:
  ebpf:
    # Increase buffer sizes for high-volume events
    process:
      buffer_size: 16384
      timeout: 10s
    network:
      buffer_size: 32768
      timeout: 10s
    dns:
      buffer_size: 16384
      timeout: 10s

# Increase pod resources
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

### For Resource-Constrained Clusters

```yaml
agent:
  ebpf:
    # Disable expensive monitors
    file:
      enabled: false
    capability:
      enabled: false

    # Reduce buffer sizes
    process:
      buffer_size: 2048
      timeout: 10s
    network:
      buffer_size: 2048
      timeout: 10s

# Reduce pod resources
resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 200m
    memory: 256Mi
```

## Security Best Practices

### 1. API Token Management

```bash
# Use Kubernetes Secrets (not environment variables)
kubectl create secret generic elf-owl-api-token \
  --from-literal=api-token=YOUR_TOKEN \
  -n kube-system

# Reference secret in ConfigMap or values
owl_api:
  auth:
    tokenSecretRef:
      name: elf-owl-api-token
      key: api-token
```

### 2. Network Policies

```yaml
# Restrict elf-owl egress to only Owl platform
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: elf-owl-egress
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      app: elf-owl
  policyTypes:
    - Egress
  egress:
    # Allow DNS queries
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53

    # Allow HTTPS to Owl platform
    - to:
        - podSelector:
            matchLabels:
              app: owl-platform
      ports:
        - protocol: TCP
          port: 443
```

### 3. Pod Security Policy

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: elf-owl-psp
spec:
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - NET_RAW
    - NET_ADMIN
  allowedCapabilities:
    - SYS_RESOURCE
    - SYS_ADMIN
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'MustRunAs'
  fsGroup:
    rule: 'MustRunAs'
```

### 4. RBAC Restrictions

The minimum required RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: elf-owl
rules:
  # Read pod information
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]

  # Read pod metadata
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]

  # Read service accounts
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["get", "list"]

  # Read network policies
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list"]

**ConfigMap rules (optional):** If you opt in to rules from ConfigMap, grant read access to `configmaps` and enable the rules source:

- Helm: `--set rules.configMap.enabled=true`
- Kustomize: `kubectl apply -k deploy/kustomize/overlays/with-rules`
```

## Monitoring elf-owl

### Health Checks

```bash
# Check if elf-owl is responsive
kubectl exec -it pod/elf-owl-abc12 -n kube-system -- elf-owl health

# Expected output:
# Status: Healthy
# Monitors: All active
# Events processed: 12345
# Last push: 30 seconds ago
```

### Metrics Endpoint

elf-owl exposes Prometheus metrics:

```bash
# Port-forward to metrics endpoint
kubectl port-forward -n kube-system pod/elf-owl-abc12 8000:8000

# Scrape metrics
curl http://localhost:8000/metrics
```

### Log Aggregation

```bash
# Collect logs from all elf-owl pods
kubectl logs -n kube-system -l app=elf-owl --tail=1000 > elf-owl-logs.txt

# Use with log aggregation service
kubectl logs -n kube-system -l app=elf-owl -f | \
  grep -i error | \
  jq '.level' | sort | uniq -c
```

## Upgrading elf-owl

### Via Helm

```bash
# Update repository
helm repo update

# Check for new versions
helm search repo elf-owl

# Upgrade
helm upgrade elf-owl elf-owl/elf-owl -n kube-system

# Monitor rollout
kubectl rollout status daemonset/elf-owl -n kube-system
```

### Via kubectl

```bash
# Update manifests
kubectl apply -f k8s/

# Monitor rollout
kubectl rollout status daemonset/elf-owl -n kube-system

# Verify new version
kubectl describe daemonset -n kube-system elf-owl | grep Image
```

## Uninstalling elf-owl

### Via Helm

```bash
helm uninstall elf-owl -n kube-system
```

### Via kubectl

```bash
kubectl delete daemonset -n kube-system elf-owl
kubectl delete clusterrole elf-owl
kubectl delete clusterrolebinding elf-owl
kubectl delete serviceaccount -n kube-system elf-owl
kubectl delete configmap -n kube-system elf-owl-config
kubectl delete secret -n kube-system elf-owl-api-token
```

### Data Cleanup

Events captured by elf-owl are stored on the Owl platform and do not leave residual data on cluster nodes.

## Next Steps

- **Configuration**: See [USAGE.md](USAGE.md) for configuration details
- **Troubleshooting**: See troubleshooting section above for common issues
- **Monitoring**: Set up log aggregation and metrics collection
- **Integration**: Connect to your SIEM or compliance platform
- **Custom Rules**: Create custom rules for your environment

## Support & Resources

- **Documentation**: See [USAGE.md](USAGE.md) for comprehensive usage guide
- **Issues**: Report issues via GitHub issues tracker
- **Logs**: Always include `kubectl logs` output when reporting issues
- **Debug Mode**: Enable with `LOG_LEVEL=debug` environment variable
