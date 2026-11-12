"""Auth-only fixed-window limits. Identifiers must use the account canonicalizer."""

import asyncio
import hmac
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from typing import cast

from redis.asyncio import Redis
from redis.exceptions import RedisError
from starlette.responses import JSONResponse

from veriq.auth_audit import RequestContext

_LIMIT = """
local wait = 0
for index, key in ipairs(KEYS) do
    if tonumber(redis.call('GET', key) or '0') >= tonumber(ARGV[index]) then
        local ttl = redis.call('PTTL', key)
        if ttl < 0 then return -1 end
        wait = math.max(wait, ttl, 1)
    end
end
if wait > 0 then return wait end
for _, key in ipairs(KEYS) do
    if redis.call('INCR', key) == 1 then redis.call('PEXPIRE', key, ARGV[3]) end
end
return 0
"""


class AuthCategory(StrEnum):
    REGISTRATION = "registration"
    EMAIL_VERIFY = "email_verify"
    EMAIL_RESEND = "email_resend"
    LOGIN = "login"
    MFA = "mfa"
    PASSWORD_RESET = "password_reset"
    PASSWORD_RESET_CONFIRM = "password_reset_confirm"
    PASSWORD_CHANGE = "password_change"
    MFA_RECOVERY = "mfa_recovery"
    ORGANIZATION_JOIN = "organization_join"


@dataclass(frozen=True)
class LimitBudget:
    ip: int
    identifier: int
    ttl_seconds: int

    def __post_init__(self) -> None:
        if min(self.ip, self.identifier, self.ttl_seconds) <= 0:
            raise ValueError("Auth limits must be positive")


class AuthLimitRejected(Exception):
    def __init__(self, retry_after: int | None = None) -> None:
        super().__init__("Auth rate limit rejected the operation")
        self.retry_after = retry_after

    def response(self, context: RequestContext) -> JSONResponse:
        unavailable = self.retry_after is None
        return JSONResponse(
            {
                "error": {
                    "code": "SERVICE_UNAVAILABLE" if unavailable else "RATE_LIMITED",
                    "message": "Try again later.",
                    "request_id": str(context.request_id),
                    "details": {},
                }
            },
            status_code=503 if unavailable else 429,
            headers={} if unavailable else {"Retry-After": str(self.retry_after)},
        )


def _address(value: str) -> IPv4Address | IPv6Address:
    if "%" in value:
        raise ValueError("Scoped IP addresses are unsupported")
    address = ip_address(value.strip())
    return (
        address.ipv4_mapped or address if isinstance(address, IPv6Address) else address
    )


def trusted_client_ip(
    peer: str,
    forwarded_for: str | None,
    trusted_proxies: Sequence[IPv4Network | IPv6Network],
) -> IPv4Address | IPv6Address:
    """Accept a single address overwritten by an explicitly trusted edge proxy."""
    direct = _address(peer)
    if not any(direct in network for network in trusted_proxies):
        return direct
    if forwarded_for is None:
        raise ValueError("Trusted proxy must supply the client address")
    return _address(forwarded_for)


class AuthRateLimiter:
    def __init__(
        self, redis: Redis, key: bytes, budgets: Mapping[AuthCategory, LimitBudget]
    ) -> None:
        if len(key) < 32 or set(budgets) != set(AuthCategory):
            raise ValueError(
                "Auth limiter requires a 32-byte key and all category budgets"
            )
        self.redis = redis
        self._key = key
        self.budgets = dict(budgets)

    def _redis_key(self, category: AuthCategory, dimension: str, value: str) -> str:
        message = f"veriq:auth:{category}:{dimension}:{value}".encode()
        return f"veriq:auth:{hmac.digest(self._key, message, 'sha256').hex()}"

    async def check(
        self,
        category: AuthCategory,
        client_ip: IPv4Address | IPv6Address,
        normalized_identifier: str,
    ) -> None:
        budget = self.budgets[category]
        try:
            async with asyncio.timeout(2):
                result = await cast(
                    Awaitable[object],
                    self.redis.eval(
                        _LIMIT,
                        2,
                        self._redis_key(category, "ip", str(client_ip)),
                        self._redis_key(category, "id", normalized_identifier),
                        str(budget.ip),
                        str(budget.identifier),
                        str(budget.ttl_seconds * 1000),
                    ),
                )
        except (RedisError, TimeoutError):
            raise AuthLimitRejected() from None
        if not isinstance(result, int) or result < 0:
            raise AuthLimitRejected()
        if result:
            raise AuthLimitRejected((result + 999) // 1000)
