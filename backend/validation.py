import ipaddress
from urllib.parse import urlparse


def validate_target(target: str):
    """
    Accept any of the following for local/lab scanning:
      - Bare IPv4 address:          192.168.1.1
      - IPv4 with port:             192.168.1.1:8080
      - http/https URL to IP:       http://192.168.1.1:8080
      - http/https URL to hostname: http://vulnerable.lab/app
    """
    target = target.strip()
    if not target:
        return False, "EMPTY_TARGET"

    # Bare IP or IP:port (no scheme)
    if not target.startswith("http://") and not target.startswith("https://"):
        host = target.split(":")[0]
        try:
            ipaddress.ip_address(host)
            return True, "VALID"
        except ValueError:
            return False, "INVALID_FORMAT: must be an IP address or http/https URL"

    # URL with scheme
    parsed = urlparse(target)
    if not parsed.hostname:
        return False, "INVALID_FORMAT: could not parse hostname from URL"

    return True, "VALID"