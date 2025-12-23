package kubernetes.admission.kubeshark.namespace_restrictions

# Test: Restricted namespace - should be denied
test_deny_restricted_namespace_kube_system {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "kubeshark-config",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "data": {
                    "namespaces": "default,kube-system,production"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "kube-system")
    contains(msg, "DENIED")
}

# Test: Restricted namespace - vault
test_deny_restricted_namespace_vault {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "kubeshark-config",
                    "labels": {
                        "app": "kubeshark"
                    }
                },
                "data": {
                    "namespaces": "vault, production"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "vault")
}

# Test: Allowed namespaces - should pass
test_allow_safe_namespaces {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "kubeshark-config",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "data": {
                    "namespaces": "default,staging,development"
                }
            }
        }
    }
    
    count(deny) == 0
}

# Test: Sensitive namespace without approval - should warn
test_warn_sensitive_namespace_without_approval {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "kubeshark-config",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "data": {
                    "namespaces": "production,staging"
                }
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "production")
    contains(msg, "approval")
}

# Test: Sensitive namespace with approval - should pass
test_allow_sensitive_namespace_with_approval {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "kubeshark-config",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    },
                    "annotations": {
                        "kubeshark.io/sensitive-approved": "true"
                    }
                },
                "data": {
                    "namespaces": "production"
                }
            }
        }
    }
    
    count(warn) == 0
}

# Test: DaemonSet without namespace filter - should deny
test_deny_daemonset_without_namespace_filter {
    input := {
        "request": {
            "object": {
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": {
                    "name": "kubeshark-worker",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "kubeshark",
                                    "image": "kubeshark/kubeshark:latest",
                                    "args": ["start"]
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "namespace filtering")
}

# Test: DaemonSet with namespace filter in args - should pass
test_allow_daemonset_with_namespace_filter_args {
    input := {
        "request": {
            "object": {
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": {
                    "name": "kubeshark-worker",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "kubeshark",
                                    "image": "kubeshark/kubeshark:latest",
                                    "args": ["start", "--namespaces", "default,staging"]
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    
    count(deny) == 0
}

# Test: DaemonSet with namespace filter in env - should pass
test_allow_daemonset_with_namespace_filter_env {
    input := {
        "request": {
            "object": {
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": {
                    "name": "kubeshark-worker",
                    "labels": {
                        "app.kubernetes.io/name": "kubeshark"
                    }
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "kubeshark",
                                    "image": "kubeshark/kubeshark:latest",
                                    "env": [
                                        {
                                            "name": "KUBESHARK_NAMESPACES",
                                            "value": "default,staging"
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    
    count(deny) == 0
}

# Test: Non-Kubeshark resource - should be ignored
test_ignore_non_kubeshark {
    input := {
        "request": {
            "object": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "my-app-config"
                },
                "data": {
                    "namespaces": "kube-system"
                }
            }
        }
    }
    
    count(deny) == 0
    count(warn) == 0
}
