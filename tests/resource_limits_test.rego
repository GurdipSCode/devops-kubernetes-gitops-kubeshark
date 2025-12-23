package kubernetes.admission.kubeshark.resource_limits

# Test: DaemonSet without resource limits - should deny
test_deny_no_resource_limits {
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
                                    "image": "kubeshark/kubeshark:latest"
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
    contains(msg, "resource limits")
}

# Test: DaemonSet without memory limit - should deny
test_deny_no_memory_limit {
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
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m"
                                        }
                                    }
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
    contains(msg, "memory limit")
}

# Test: DaemonSet with excessive memory limit - should warn
test_warn_excessive_memory_limit {
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
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m",
                                            "memory": "4Gi"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "memory limit")
    contains(msg, "exceeds")
}

# Test: DaemonSet with appropriate limits - should pass
test_allow_appropriate_limits {
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
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m",
                                            "memory": "512Mi"
                                        },
                                        "requests": {
                                            "cpu": "100m",
                                            "memory": "256Mi"
                                        }
                                    }
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

# Test: ConfigMap without retention period - should deny
test_deny_no_retention_period {
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
                    "max-capture-size-mb": "100"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "retention period")
}

# Test: ConfigMap with excessive retention period - should deny
test_deny_excessive_retention {
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
                    "retention-hours": "72",
                    "max-capture-size-mb": "100"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "retention period")
    contains(msg, "exceeds")
}

# Test: ConfigMap without capture size limit - should deny
test_deny_no_capture_size_limit {
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
                    "retention-hours": "12"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "max capture size")
}

# Test: ConfigMap with excessive capture size - should deny
test_deny_excessive_capture_size {
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
                    "retention-hours": "12",
                    "max-capture-size-mb": "1000"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "max capture size")
    contains(msg, "exceeds")
}

# Test: ConfigMap with appropriate settings - should pass
test_allow_appropriate_config {
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
                    "retention-hours": "12",
                    "max-capture-size-mb": "200"
                }
            }
        }
    }
    
    count(deny) == 0
}

# Test: DaemonSet without node selector - should warn
test_warn_no_node_selector {
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
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m",
                                            "memory": "512Mi"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "node selector")
    contains(msg, "ALL nodes")
}

# Test: DaemonSet with node selector - should not warn about nodes
test_allow_with_node_selector {
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
                            "nodeSelector": {
                                "node-role.kubernetes.io/worker": "true"
                            },
                            "containers": [
                                {
                                    "name": "kubeshark",
                                    "image": "kubeshark/kubeshark:latest",
                                    "resources": {
                                        "limits": {
                                            "cpu": "500m",
                                            "memory": "512Mi"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    
    # Should not warn about node selector
    node_selector_warnings := [msg | 
        msg := warn[_]
        contains(msg, "node selector")
    ]
    count(node_selector_warnings) == 0
}
