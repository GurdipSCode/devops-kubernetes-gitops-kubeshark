package kubernetes.admission.kubeshark.data_filtering

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Kubeshark Sensitive Data Filtering
# description: Ensures Kubeshark has proper filters to redact sensitive data
# version: 1.0.0
# severity: CRITICAL
# category: Security
# custom:
#   matchers:
#     kinds:
#       - apiGroups: [""]
#         kinds: ["ConfigMap"]
#       - apiGroups: ["apps"]
#         kinds: ["Deployment"]

# Sensitive headers that MUST be redacted
required_redacted_headers := {
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "X-API-Key",
    "X-Auth-Token",
    "X-CSRF-Token",
    "Proxy-Authorization",
    "WWW-Authenticate",
}

# Sensitive query parameters that MUST be redacted
required_redacted_params := {
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "client_secret",
}

# Sensitive JSON fields that MUST be redacted
required_redacted_json_fields := {
    "password",
    "token",
    "secret",
    "apiKey",
    "accessToken",
    "refreshToken",
    "privateKey",
    "clientSecret",
    "creditCard",
    "ssn",
    "bankAccount",
}

# Check if this is a Kubeshark ConfigMap
is_kubeshark_config if {
    input.request.object.kind == "ConfigMap"
    input.request.object.metadata.labels["app.kubernetes.io/name"] == "kubeshark"
}

is_kubeshark_config if {
    input.request.object.kind == "ConfigMap"
    contains(input.request.object.metadata.name, "kubeshark")
}

# CRITICAL: ConfigMap must have header redaction configured
deny[msg] {
    is_kubeshark_config
    
    # Check if header redaction is configured
    not has_header_redaction
    
    msg := sprintf(
        "CRITICAL: Kubeshark ConfigMap '%s' MUST have header redaction configured to prevent capturing Authorization, Cookie, and API keys. Required redacted headers: %v",
        [input.request.object.metadata.name, required_redacted_headers]
    )
}

# CRITICAL: All required headers must be in redaction list
deny[msg] {
    is_kubeshark_config
    has_header_redaction
    
    # Get configured redacted headers
    config_data := input.request.object.data
    redacted_headers_str := object.get(config_data, "redacted-headers", "")
    redacted_headers := {h | h := split(redacted_headers_str, ",")[_]; trim_space(h) != ""}
    
    # Check each required header
    required_header := required_redacted_headers[_]
    not header_is_redacted(required_header, redacted_headers)
    
    msg := sprintf(
        "CRITICAL: Kubeshark must redact header '%s'. Add to redacted-headers configuration.",
        [required_header]
    )
}

# CRITICAL: Query parameter redaction must be configured
deny[msg] {
    is_kubeshark_config
    
    not has_query_param_redaction
    
    msg := sprintf(
        "CRITICAL: Kubeshark ConfigMap '%s' MUST have query parameter redaction for sensitive params: %v",
        [input.request.object.metadata.name, required_redacted_params]
    )
}

# CRITICAL: JSON body redaction for sensitive fields
deny[msg] {
    is_kubeshark_config
    
    not has_json_redaction
    
    msg := sprintf(
        "CRITICAL: Kubeshark ConfigMap '%s' MUST have JSON body redaction for fields like password, token, secret, apiKey, creditCard",
        [input.request.object.metadata.name]
    )
}

# WARNING: PCI compliance - credit card pattern redaction
warn[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    
    # Check if credit card regex is configured
    not object.get(config_data, "redact-credit-cards", false)
    
    msg := "WARNING: For PCI compliance, enable credit card pattern redaction (redact-credit-cards: true)"
}

# WARNING: HIPAA compliance - SSN pattern redaction
warn[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    
    # Check if SSN regex is configured
    not object.get(config_data, "redact-ssn", false)
    
    msg := "WARNING: For HIPAA compliance, enable SSN pattern redaction (redact-ssn: true)"
}

# WARNING: Email address redaction for GDPR
warn[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    
    # Check if email redaction is configured
    not object.get(config_data, "redact-emails", false)
    
    msg := "WARNING: For GDPR compliance, consider enabling email address redaction (redact-emails: true)"
}

# CRITICAL: Kubernetes secret paths must be excluded
deny[msg] {
    is_kubeshark_config
    
    config_data := input.request.object.data
    excluded_paths := object.get(config_data, "excluded-paths", "")
    
    # Check if /api/v1/secrets is excluded
    not contains(excluded_paths, "/api/v1/secrets")
    
    msg := "CRITICAL: Kubeshark must exclude Kubernetes API paths that return secrets. Add '/api/v1/secrets' to excluded-paths"
}

# Helpers
has_header_redaction if {
    input.request.object.data["redacted-headers"]
}

has_query_param_redaction if {
    input.request.object.data["redacted-query-params"]
}

has_json_redaction if {
    input.request.object.data["redacted-json-fields"]
}

header_is_redacted(required, configured) if {
    configured_lower := {lower(h) | h := configured[_]}
    lower(required) in configured_lower
}

trim_space(s) = trimmed {
    trimmed := trim(s, " \t\n")
}
