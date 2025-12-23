package kubernetes.admission.kubeshark.rbac

# Test: ClusterRole with secrets access - should deny
test_deny_secrets_access {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "kubeshark-viewer",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods", "services", "secrets"],
                        "verbs": ["get", "list", "watch"]
                    }
                ]
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "secrets")
    contains(msg, "CRITICAL")
}

# Test: ClusterRole with wildcard resources - should deny
test_deny_wildcard_resources {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "kubeshark-admin"
                },
                "rules": [
                    {
                        "apiGroups": ["*"],
                        "resources": ["*"],
                        "verbs": ["get", "list"]
                    }
                ]
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "wildcard")
}

# Test: ClusterRole with wildcard verbs - should deny
test_deny_wildcard_verbs {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "kubeshark-viewer",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["*"]
                    }
                ]
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "wildcard")
    contains(msg, "verb")
}

# Test: ClusterRoleBinding to cluster-admin - should deny
test_deny_cluster_admin_binding {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {
                    "name": "kubeshark-admin"
                },
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "cluster-admin"
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "kubeshark",
                        "namespace": "default"
                    }
                ]
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "cluster-admin")
}

# Test: ClusterRole with read-only permissions - should pass
test_allow_readonly_permissions {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "kubeshark-viewer",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods", "services", "endpoints"],
                        "verbs": ["get", "list", "watch"]
                    }
                ]
            }
        }
    }
    
    count(deny) == 0
}

# Test: ClusterRole modifying ConfigMaps - should warn
test_warn_configmap_modification {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "kubeshark-manager",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "verbs": ["get", "list", "create", "update"]
                    }
                ]
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "ConfigMaps")
}

# Test: ClusterRole with RBAC escalation - should deny
test_deny_rbac_escalation {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "kubeshark-admin",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "rules": [
                    {
                        "apiGroups": ["rbac.authorization.k8s.io"],
                        "resources": ["clusterroles"],
                        "verbs": ["create", "escalate"]
                    }
                ]
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "privilege escalation")
}

# Test: ServiceAccount with automountServiceAccountToken=true for dashboard - should deny
test_deny_automount_token_dashboard {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": "kubeshark-dashboard"
                },
                "automountServiceAccountToken": true
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "automountServiceAccountToken")
    contains(msg, "false")
}

# Test: ServiceAccount with automountServiceAccountToken=false - should pass
test_allow_no_automount_token {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": "kubeshark-dashboard"
                },
                "automountServiceAccountToken": false
            }
        }
    }
    
    count(deny) == 0
}

# Test: Non-Kubeshark ClusterRole - should be ignored
test_ignore_non_kubeshark {
    input := {
        "request": {
            "object": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {
                    "name": "my-app-viewer"
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["secrets"],
                        "verbs": ["*"]
                    }
                ]
            }
        }
    }
    
    count(deny) == 0
}
