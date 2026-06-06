import re


def defang_url(url: str) -> str:
    """
    Defang a URL for safe sharing in reports.
    hxxp://example[.]com/path
    """
    if not url:
        return url
    url = url.replace("http://", "hxxp://")
    url = url.replace("https://", "hxxps://")
    url = url.replace("ftp://", "fxp://")
    parts = url.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        url = "/".join(parts)
    else:
        url = url.replace(".", "[.]")
    return url


def defang_ip(ip: str) -> str:
    """
    Defang an IP address.
    1.2.3.4 -> 1.2.3[.]4
    """
    if not ip:
        return ip
    parts = ip.rsplit(".", 1)
    if len(parts) == 2:
        return f"{parts[0]}[.]{parts[1]}"
    return ip


def defang_email(email: str) -> str:
    """
    Defang an email address.
    user@example.com -> user[@]example[.]com
    """
    if not email:
        return email
    email = email.replace("@", "[@]")
    parts = email.split("[@]", 1)
    if len(parts) == 2:
        parts[1] = parts[1].replace(".", "[.]")
        email = "[@]".join(parts)
    return email


def defang_value(entity_type: str, value: str) -> str:
    """
    Defang an entity value based on its type.
    Returns the defanged version for display.
    """
    if entity_type in (
        "ONION_URL",
        "DOMAIN",
    ):
        return defang_url(value)
    elif entity_type == "IP_ADDRESS":
        return defang_ip(value)
    elif entity_type == "EMAIL_ADDRESS":
        return defang_email(value)
    else:
        return value


def defang_text(text: str) -> str:
    """
    Defang all URLs and IPs found in free text.
    Use for report summaries and context snippets.
    """
    if not text:
        return text

    text = re.sub(
        r'https?://',
        lambda m: m.group().replace(
            "http://", "hxxp://"
        ).replace(
            "https://", "hxxps://"
        ),
        text
    )

    text = re.sub(
        r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})'
        r'\.(\d{1,3})\b',
        r'\1.\2.\3[.]\4',
        text,
    )

    return text