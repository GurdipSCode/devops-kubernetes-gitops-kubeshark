package kubernetes.admission.kubeshark.namespace_restrictions

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Kubeshark Namespace Capture Restrictions
# description: Controls which namespaces Kubeshark is allowed to capture traffic from
# version: 1.0.0
# severity: HIGH
# category: Security
# custom:
#   matchers:
#     kinds:
#       - apiGroups: [""]
#         kinds: ["ConfigMap"]
#       - apiGroups: ["apps"]
#         kinds: ["DaemonSet", "Deployment"]

# Restricted namespaces - Kubeshark should NEVER capture these
restricted_namespaces := {
    "kube-system",           # Core Kubernetes components
    "kube-public",           # Public cluster info
    "kube-node-lease",       # Node heartbeats
    "cattle-system",         # Rancher management
    "fleet-system",          # Fleet management
    "cert-manager",          # Certificate management (secrets!)
    "vault",                 # Vault secrets
    "sealed-secrets",        # Sealed secrets controller
    "external-secrets",      # External secrets operator
}

# Sensitive namespaces - require explicit approval
sensitive_namespaces := {
    "production",
    "prod",
    "finance",
    "payment",
    "pci",
    "hipaa",
    "banking",
}

# Check if this is a Kubeshark resource
is_kubeshark if {
    input.request.object.metadata.labels["app.kubernetes.io/name"] == "kubeshark"
}

is_kubeshark if {
    input.request.object.metadata.labels.app == "kubeshark"
}

is_kubeshark if {
    contains(input.request.object.metadata.name, "kubeshark")
}

# Violation: Kubeshark trying to capture restricted namespace
deny[msg] {
    is_kubeshark
    
    # Check if ConfigMap contains namespace filter
    input.request.object.kind == "ConfigMap"
    namespaces := input.request.object.data.namespaces
    
    # Parse namespace list (comma or space separated)
    namespace_list := split(namespaces, ",")
    namespace := namespace_list[_]
    trimmed := trim_space(namespace)
    
    restricted_namespaces[trimmed]
    
    msg := sprintf(
        "DENIED: Kubeshark cannot capture traffic from restricted namespace '%s'. Restricted namespaces: %v",
        [trimmed, restricted_namespaces]
    )
}

# Violation: Kubeshark DaemonSet without namespace restrictions
deny[msg] {
    is_kubeshark
    input.request.object.kind == "DaemonSet"
    
    # Check if namespace filtering is configured
    containers := input.request.object.spec.template.spec.containers
    container := containers[_]
    container.name == "kubeshark"
    
    # Look for namespace filter in args or env
    not has_namespace_filter(container)
    
    msg := sprintf(
        "DENIED: Kubeshark DaemonSet '%s' must have namespace filtering configured to prevent capturing restricted namespaces",
        [input.request.object.metadata.name]
    )
}

# Warning: Kubeshark capturing sensitive namespace
warn[msg] {
    is_kubeshark
    input.request.object.kind == "ConfigMap"
    
    namespaces := input.request.object.data.namespaces
    namespace_list := split(namespaces, ",")
    namespace := namespace_list[_]
    trimmed := trim_space(namespace)
    
    sensitive_namespaces[trimmed]
    
    # Check for approval annotation
    not input.request.object.metadata.annotations["kubeshark.io/sensitive-approved"]
    
    msg := sprintf(
        "WARNING: Kubeshark capturing sensitive namespace '%s' requires approval annotation 'kubeshark.io/sensitive-approved=true'",
        [trimmed]
    )
}

# Helper: Check if container has namespace filter configured
has_namespace_filter(container) if {
    container.args[_] contains "--namespaces"
}

has_namespace_filter(container) if {
    env := container.env[_]
    env.name == "KUBESHARK_NAMESPACES"
}

# Helper function
trim_space(s) = trimmed {
    trimmed := trim(s, " \t\n")
}
