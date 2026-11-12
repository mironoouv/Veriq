"""Integration probe executed inside the API image against Compose Redis."""

import asyncio
import sys
from ipaddress import ip_address, ip_network
from uuid import uuid4

from veriq.auth_audit import RequestContext
from veriq.auth_rate_limit import (
    AuthCategory,
    AuthLimitRejected,
    AuthRateLimiter,
    LimitBudget,
    trusted_client_ip,
)
from veriq.redis_client import create_redis


async def main(outage: bool) -> None:
    redis = create_redis()
    try:
        key = uuid4().bytes + uuid4().bytes
        limiter = AuthRateLimiter(
            redis, key, dict.fromkeys(AuthCategory, LimitBudget(5, 3, 30))
        )
        identifier = "auth-smoke@example.invalid"
        peer = trusted_client_ip(
            "192.0.2.1", "203.0.113.8", [ip_network("10.0.0.0/24")]
        )
        assert peer == ip_address("192.0.2.1")
        assert trusted_client_ip(
            "10.0.0.2", "203.0.113.8", [ip_network("10.0.0.0/24")]
        ) == ip_address("203.0.113.8")
        try:
            trusted_client_ip(
                "10.0.0.2", "203.0.113.8, 192.0.2.1", [ip_network("10.0.0.0/24")]
            )
        except ValueError:
            pass
        else:
            raise AssertionError("A trusted edge must overwrite forwarded addresses")

        async def check(account: str, client: str = str(peer)) -> int:
            try:
                await limiter.check(AuthCategory.LOGIN, ip_address(client), account)
            except AuthLimitRejected as error:
                response = error.response(RequestContext.new())
                assert identifier.encode() not in response.body
                if not outage:
                    assert 1 <= int(response.headers["Retry-After"]) <= 30
                return response.status_code
            return 200

        if outage:
            assert await check(identifier) == 503
            print("Auth Redis outage: sensitive operations fail closed")
            return
        statuses = await asyncio.gather(*(check(identifier) for _ in range(20)))
        assert statuses.count(200) == 3 and statuses.count(429) == 17
        assert await check(identifier, "203.0.113.9") == 429
        assert await check("other@example.invalid") == 200
        assert await check("another@example.invalid") == 200
        assert await check("third@example.invalid") == 429
        for category in AuthCategory:
            if category != AuthCategory.LOGIN:
                await limiter.check(category, peer, identifier)
        keys = await redis.keys("veriq:auth:*")
        assert keys and all(len(value) == len("veriq:auth:") + 64 for value in keys)
        assert all(
            identifier.encode() not in value and str(peer).encode() not in value
            for value in keys
        )
        print(
            "Auth Redis: concurrent quotas, isolated categories, opaque keys and forwarded IP passed"
        )
    finally:
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:] == ["outage"]))
