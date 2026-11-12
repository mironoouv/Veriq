from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from veriq.mfa_crypto import FactorKeys, matching_counter, totp


@pytest.mark.parametrize(
    ("tick", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_sha1_vectors(tick: int, expected: str) -> None:
    assert totp(b"12345678901234567890", tick // 30, 8) == expected


def test_window_and_encrypted_factor_binding() -> None:
    seed = b"12345678901234567890"
    assert matching_counter(seed, totp(seed, 10), 329) == 10
    assert matching_counter(seed, totp(seed, 9), 329) == 9
    assert matching_counter(seed, totp(seed, 8), 329) is None
    assert matching_counter(seed, "1234", 329) is None
    user, factor = uuid4(), uuid4()
    ring = FactorKeys("new", {"old": b"a" * 32, "new": b"b" * 32})
    encrypted = ring.encrypt(user, factor, seed)
    assert seed not in encrypted
    assert ring.decrypt(user, factor, "new", encrypted) == seed
    with pytest.raises(InvalidTag):
        ring.decrypt(uuid4(), factor, "new", encrypted)
    with pytest.raises(InvalidTag):
        ring.decrypt(user, factor, "old", encrypted)
