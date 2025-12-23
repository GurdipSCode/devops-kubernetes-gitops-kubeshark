package kubernetes.admission.kubeshark.resource_limits

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Kubeshark Resource Limits and Retention
# description: Ensures Kubeshark has appropriate resource limits and data retention policies
# version: 1.0.0
# severity: HIGH
# category: Operations
# custom:
#   matchers:
#     kinds:
#       - apiGroups: ["apps"]
#         kinds: ["DaemonSet", "Deployment"]
#       - apiGroups: [""]
#         kinds: ["ConfigMap"]

# Maximum allowed retention period (in hours)
max_retention_hours := 24

# Maximum capture size per pod (in MB)
max_capture_size_mb := 500

# Resource limits
min_memory_limit := "256Mi"
max_memory_limit := "2Gi"
min_cpu_limit := "100m"
max_cpu_limit := "1000m"

# Check if this is a Kubeshark DaemonSet/Deployment
is_kubeshark_workload if {
    input.request.object.kind in ["DaemonSet", "Deployment"]
    input.request.object.metadata.labels["app.kubernetes.io/name"] == "kubeshark"
}

is_kubeshark_workload if {
    input.request.object.kind in ["DaemonSet", "Deployment"]
    contains(input.request.object.metadata.name, "kubeshark")
}

is_kubeshark_config if {
    input.request.object.kind == "ConfigMap"
    input.request.object.metadata.labels["app.kubernetes.io/name"] == "kubeshark"
}

# CRITICAL: DaemonSet/Deployment must have resource limits
deny[msg] {
    is_kubeshark_workload
    
    containers := input.request.object.spec.template.spec.containers
    container := containers[_]
    container.name == "kubeshark"
    
    not container.resources.limits
    
    msg := sprintf(
        "CRITICAL: Kubeshark container must have resource limits. Kubeshark captures network traffic and can consume significant resources.",
        []
    )
}

# CRITICAL: Memory limit must be set and reasonable
deny[msg] {
    is_kubeshark_workload
    
    containers := input.request.object.spec.template.spec.containers
    container := containers[_]
    container.name == "kubeshark"
    
    not container.resources.limits.memory
    
    msg := sprintf(
        "CRITICAL: Kubeshark container must have memory limit set (recommended: %s to %s)",
        [min_memory_limit, max_memory_limit]
    )
}

# WARNING: Memory limit is too high
warn[msg] {
    is_kubeshark_workload
    
    containers := input.request.object.spec.template.spec.containers
    container := containers[_]
    container.name == "kubeshark"
    
    memory_limit := container.resources.limits.memory
    memory_bytes := convert_to_bytes(memory_limit)
    max_bytes := convert_to_bytes(max_memory_limit)
    
    memory_bytes > max_bytes
    
    msg := sprintf(
        "WARNING: Kubeshark memory limit '%s' exceeds recommended maximum '%s'. High memory limits can impact cluster stability.",
        [memory_limit, max_memory_limit]
    )
}

# CRITICAL: CPU limit must be set
deny[msg] {
    is_kubeshark_workload
    
    containers := input.request.object.spec.template.spec.containers
    container := containers[_]
    container.name == "kubeshark"
    
    not container.resources.limits.cpu
    
    msg := sprintf(
        "CRITICAL: Kubeshark container must have CPU limit set (recommended: %s to %s)",
        [min_cpu_limit, max_cpu_limit]
    )
}

# CRITICAL: Retention period must be configured
deny[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    not config_data["retention-hours"]
    
    msg := sprintf(
        "CRITICAL: Kubeshark must have retention period configured. Maximum allowed: %d hours",
        [max_retention_hours]
    )
}

# CRITICAL: Retention period exceeds maximum
deny[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    retention_str := config_data["retention-hours"]
    retention := to_number(retention_str)
    
    retention > max_retention_hours
    
    msg := sprintf(
        "CRITICAL: Kubeshark retention period %d hours exceeds maximum allowed %d hours. Long retention increases security and compliance risks.",
        [retention, max_retention_hours]
    )
}

# CRITICAL: Capture size limit must be configured
deny[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    not config_data["max-capture-size-mb"]
    
    msg := sprintf(
        "CRITICAL: Kubeshark must have max capture size configured. Maximum allowed: %d MB",
        [max_capture_size_mb]
    )
}

# CRITICAL: Capture size exceeds maximum
deny[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    size_str := config_data["max-capture-size-mb"]
    size := to_number(size_str)
    
    size > max_capture_size_mb
    
    msg := sprintf(
        "CRITICAL: Kubeshark max capture size %d MB exceeds maximum allowed %d MB",
        [size, max_capture_size_mb]
    )
}

# WARNING: No storage class defined for persistent captures
warn[msg] {
    is_kubeshark_workload
    
    spec := input.request.object.spec.template.spec
    volumes := object.get(spec, "volumes", [])
    
    # Check if any volume is a PVC
    not has_pvc_volume(volumes)
    
    msg := "WARNING: Kubeshark should use PersistentVolumeClaim for capture storage to prevent data loss on pod restart"
}

# WARNING: DaemonSet on all nodes can be expensive
warn[msg] {
    input.request.object.kind == "DaemonSet"
    is_kubeshark_workload
    
    spec := input.request.object.spec.template.spec
    
    # Check if node selector is configured
    not spec.nodeSelector
    not spec.affinity
    
    msg := "WARNING: Kubeshark DaemonSet without node selector will run on ALL nodes. Consider limiting to specific nodes (e.g., workers only, exclude control plane)"
}

# Helpers
has_pvc_volume(volumes) if {
    volume := volumes[_]
    volume.persistentVolumeClaim
}

# Convert memory string to bytes
convert_to_bytes(mem_str) = bytes {
    endswith(mem_str, "Gi")
    num := to_number(trim_suffix(mem_str, "Gi"))
    bytes := num * 1024 * 1024 * 1024
}

convert_to_bytes(mem_str) = bytes {
    endswith(mem_str, "Mi")
    num := to_number(trim_suffix(mem_str, "Mi"))
    bytes := num * 1024 * 1024
}

convert_to_bytes(mem_str) = bytes {
    endswith(mem_str, "Ki")
    num := to_number(trim_suffix(mem_str, "Ki"))
    bytes := num * 1024
}

convert_to_bytes(mem_str) = bytes {
    not contains(mem_str, "i")
    bytes := to_number(mem_str)
}
