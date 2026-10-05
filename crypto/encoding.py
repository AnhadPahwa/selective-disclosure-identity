import base64

from typing import Union

def b64url_encode(data: bytes) -> str:
    """Encode bytes to a URL-safe Base64 string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64url_decode(s: Union[str, bytes]) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii")

    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))