package kubernetes.admission.kubeshark.data_filtering

# Test: ConfigMap without header redaction - should deny
test_deny_no_header_redaction {
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
                    "namespaces": "default"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "header redaction")
    contains(msg, "CRITICAL")
}

# Test: ConfigMap with header redaction but missing required headers - should deny
test_deny_incomplete_header_redaction {
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
                    "redacted-headers": "Cookie,Set-Cookie",
                    "redacted-query-params": "password,token",
                    "redacted-json-fields": "password,apiKey"
                }
            }
        }
    }
    
    # Should deny because Authorization header is missing
    count(deny) > 0
    msg := deny[_]
    contains(msg, "Authorization")
}

# Test: ConfigMap with complete header redaction - should pass
test_allow_complete_header_redaction {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-query-params": "password,token,secret,api_key,apikey,access_token,refresh_token,client_secret",
                    "redacted-json-fields": "password,token,secret,apiKey,accessToken,refreshToken,privateKey,clientSecret,creditCard,ssn,bankAccount",
                    "excluded-paths": "/api/v1/secrets"
                }
            }
        }
    }
    
    count(deny) == 0
}

# Test: Missing query param redaction - should deny
test_deny_no_query_param_redaction {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-json-fields": "password,apiKey"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "query parameter")
}

# Test: Missing JSON redaction - should deny
test_deny_no_json_redaction {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-query-params": "password,token"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "JSON body redaction")
}

# Test: Missing secrets path exclusion - should deny
test_deny_no_secrets_exclusion {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-query-params": "password,token,secret,api_key",
                    "redacted-json-fields": "password,apiKey",
                    "excluded-paths": "/api/v1/configmaps"
                }
            }
        }
    }
    
    count(deny) > 0
    msg := deny[_]
    contains(msg, "/api/v1/secrets")
}

# Test: PCI compliance warning - no credit card redaction
test_warn_no_credit_card_redaction {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-query-params": "password,token,secret,api_key,apikey,access_token,refresh_token,client_secret",
                    "redacted-json-fields": "password,token,secret,apiKey",
                    "excluded-paths": "/api/v1/secrets"
                }
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "PCI")
    contains(msg, "credit card")
}

# Test: HIPAA compliance warning - no SSN redaction
test_warn_no_ssn_redaction {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-query-params": "password,token,secret,api_key,apikey,access_token,refresh_token,client_secret",
                    "redacted-json-fields": "password,token,secret,apiKey",
                    "excluded-paths": "/api/v1/secrets"
                }
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "HIPAA")
    contains(msg, "SSN")
}

# Test: GDPR compliance warning - no email redaction
test_warn_no_email_redaction {
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
                    "redacted-headers": "Authorization,Cookie,Set-Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token,Proxy-Authorization,WWW-Authenticate",
                    "redacted-query-params": "password,token,secret,api_key,apikey,access_token,refresh_token,client_secret",
                    "redacted-json-fields": "password,token,secret,apiKey",
                    "excluded-paths": "/api/v1/secrets"
                }
            }
        }
    }
    
    count(warn) > 0
    msg := warn[_]
    contains(msg, "GDPR")
    contains(msg, "email")
}

# Test: Non-Kubeshark ConfigMap - should be ignored
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
                    "key": "value"
                }
            }
        }
    }
    
    count(deny) == 0
    count(warn) == 0
}
