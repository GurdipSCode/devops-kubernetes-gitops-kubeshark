package kubernetes.admission.kubeshark.rbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Kubeshark RBAC Validation
# description: Ensures Kubeshark has appropriate RBAC permissions (not overly permissive)
# version: 1.0.0
# severity: HIGH
# category: Security
# custom:
#   matchers:
#     kinds:
#       - apiGroups: ["rbac.authorization.k8s.io"]
#         kinds: ["ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"]
#       - apiGroups: [""]
#         kinds: ["ServiceAccount"]

# Check if this is a Kubeshark RBAC resource
is_kubeshark_rbac if {
    input.request.object.kind in ["ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"]
    input.request.object.metadata.labels["app.kubernetes.io/name"] == "kubeshark"
}

is_kubeshark_rbac if {
    input.request.object.kind in ["ClusterRole", "Role"]
    contains(input.request.object.metadata.name, "kubeshark")
}

is_kubeshark_sa if {
    input.request.object.kind == "ServiceAccount"
    contains(input.request.object.metadata.name, "kubeshark")
}

# Required permissions for Kubeshark to function
required_permissions := {
    "pods": ["get", "list", "watch"],
    "services": ["get", "list"],
    "endpoints": ["get", "list"],
}

# Dangerous permissions that Kubeshark should NOT have
dangerous_permissions := {
    "secrets": ["*", "get", "list", "watch", "create", "update", "delete"],
    "configmaps": ["create", "update", "delete", "patch"],
    "nodes": ["create", "update", "delete", "patch"],
    "namespaces": ["create", "delete"],
    "persistentvolumes": ["create", "delete"],
    "clusterroles": ["*", "create", "update", "delete", "patch", "escalate", "bind"],
    "clusterrolebindings": ["*", "create", "update", "delete", "patch"],
}

# CRITICAL: Kubeshark should NOT have access to Secrets
deny[msg] {
    is_kubeshark_rbac
    input.request.object.kind in ["ClusterRole", "Role"]
    
    rule := input.request.object.rules[_]
    "secrets" in rule.resources
    verb := rule.verbs[_]
    
    # Any verb on secrets is dangerous
    msg := sprintf(
        "CRITICAL: Kubeshark ClusterRole/Role '%s' has '%s' permission on secrets. Kubeshark captures network traffic and should NEVER access Kubernetes secrets.",
        [input.request.object.metadata.name, verb]
    )
}

# CRITICAL: Kubeshark should not have wildcard permissions
deny[msg] {
    is_kubeshark_rbac
    input.request.object.kind in ["ClusterRole", "Role"]
    
    rule := input.request.object.rules[_]
    "*" in rule.resources
    
    msg := sprintf(
        "CRITICAL: Kubeshark ClusterRole/Role '%s' has wildcard (*) resource permissions. This is overly permissive and violates least privilege principle.",
        [input.request.object.metadata.name]
    )
}

# CRITICAL: Kubeshark should not have wildcard verbs
deny[msg] {
    is_kubeshark_rbac
    input.request.object.kind in ["ClusterRole", "Role"]
    
    rule := input.request.object.rules[_]
    "*" in rule.verbs
    resource := rule.resources[_]
    
    # Wildcard verbs on any resource is too permissive
    msg := sprintf(
        "CRITICAL: Kubeshark ClusterRole/Role '%s' has wildcard (*) verb on resource '%s'. Specify exact verbs needed (get, list, watch).",
        [input.request.object.metadata.name, resource]
    )
}

# CRITICAL: Kubeshark should not have cluster-admin binding
deny[msg] {
    input.request.object.kind in ["ClusterRoleBinding", "RoleBinding"]
    
    # Check if binding to cluster-admin
    input.request.object.roleRef.name == "cluster-admin"
    
    # Check if binding to Kubeshark SA
    subject := input.request.object.subjects[_]
    contains(subject.name, "kubeshark")
    
    msg := "CRITICAL: Kubeshark service account is bound to cluster-admin role. This grants full cluster access and is extremely dangerous."
}

# WARNING: Kubeshark can modify ConfigMaps
warn[msg] {
    is_kubeshark_rbac
    input.request.object.kind in ["ClusterRole", "Role"]
    
    rule := input.request.object.rules[_]
    "configmaps" in rule.resources
    verb := rule.verbs[_]
    verb in ["create", "update", "patch", "delete"]
    
    msg := sprintf(
        "WARNING: Kubeshark has '%s' permission on ConfigMaps. Consider using read-only access (get, list, watch) for Kubeshark configuration.",
        [verb]
    )
}

# WARNING: Kubeshark has Node access
warn[msg] {
    is_kubeshark_rbac
    input.request.object.kind in ["ClusterRole", "Role"]
    
    rule := input.request.object.rules[_]
    "nodes" in rule.resources
    verb := rule.verbs[_]
    verb in ["create", "update", "delete", "patch"]
    
    msg := sprintf(
        "WARNING: Kubeshark has '%s' permission on Nodes. This is usually unnecessary for traffic capture.",
        [verb]
    )
}

# CRITICAL: Kubeshark modifying RBAC is dangerous
deny[msg] {
    is_kubeshark_rbac
    input.request.object.kind in ["ClusterRole", "Role"]
    
    rule := input.request.object.rules[_]
    resource := rule.resources[_]
    resource in ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
    
    verb := rule.verbs[_]
    verb in ["create", "update", "delete", "patch", "escalate", "bind"]
    
    msg := sprintf(
        "CRITICAL: Kubeshark has '%s' permission on RBAC resource '%s'. This allows privilege escalation.",
        [verb, resource]
    )
}

# WARNING: ClusterRole instead of Role for namespace-scoped deployment
warn[msg] {
    is_kubeshark_rbac
    input.request.object.kind == "ClusterRole"
    
    # Check if all rules are for namespaced resources
    all_namespaced := [rule | 
        rule := input.request.object.rules[_]
        all_resources_namespaced(rule.resources)
    ]
    
    count(all_namespaced) == count(input.request.object.rules)
    
    msg := "WARNING: Kubeshark using ClusterRole but all resources are namespace-scoped. Consider using namespace-scoped Role instead for better isolation."
}

# CRITICAL: ServiceAccount without automountServiceAccountToken
deny[msg] {
    is_kubeshark_sa
    
    # Check if automountServiceAccountToken is explicitly set to false
    auto_mount := object.get(input.request.object, "automountServiceAccountToken", true)
    auto_mount == true
    
    # Only flag if this SA is for the dashboard/frontend (not the worker)
    contains(input.request.object.metadata.name, "dashboard")
    
    msg := "CRITICAL: Kubeshark dashboard ServiceAccount should set automountServiceAccountToken: false. Dashboard doesn't need cluster API access."
}

# Helper: Check if all resources are namespace-scoped
all_resources_namespaced(resources) if {
    cluster_scoped := {"nodes", "persistentvolumes", "clusterroles", "clusterrolebindings", "namespaces"}
    
    resource := resources[_]
    not cluster_scoped[resource]
}
