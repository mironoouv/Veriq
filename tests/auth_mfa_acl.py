"""Check MFA and independent recovery SQL entry point privileges."""

import sys

from auth_issuer_acl import DIGEST, ID, LIMITS, check

MFA = {"veriq_mfa_verifier"}
API = {"veriq_api"}
PURPOSE = "'fixture'::text"
POLICY_TYPES = "uuid,uuid,smallint,interval[]"
POLICY_ARGS = f"{ID},{ID},0::smallint,{LIMITS}"
INVOKERS = {
    f"veriq_base_session_limits({POLICY_TYPES})",
    f"veriq_session_limits({POLICY_TYPES})",
    f"veriq_pre_recovery_session_limits({POLICY_TYPES})",
    "veriq_recovery_permission(uuid,uuid,text)",
    "veriq_recovery_superadmin(uuid)",
}
FUNCTIONS = (
    ("veriq_mfa_primary(uuid,bytea,interval[])", f"{ID},{DIGEST},{LIMITS}", MFA),
    ("veriq_mfa_account(uuid,bigint)", f"{ID},1::bigint", MFA),
    ("veriq_pre_recovery_mfa_account(uuid,bigint)", f"{ID},1::bigint", set()),
    (
        "veriq_mfa_confirm(uuid,uuid,bigint,bytea,uuid)",
        f"{ID},{ID},1::bigint,{DIGEST},{ID}",
        MFA,
    ),
    ("veriq_mfa_can_disable(uuid,interval[])", f"{ID},{LIMITS}", MFA),
    ("veriq_mfa_reset_sessions(uuid)", ID, MFA),
    (
        "veriq_mfa_fresh(uuid,bytea,interval[],text,interval)",
        f"{ID},{DIGEST},{LIMITS},{PURPOSE},interval '5 minutes'",
        API | MFA,
    ),
    (
        "veriq_recovery_start(uuid,bytea,uuid,uuid,uuid)",
        f"{ID},{DIGEST},{ID},{ID},{ID}",
        API,
    ),
    (
        "veriq_recovery_transition(uuid,bytea,interval[],uuid,text,uuid,bytea,uuid,uuid)",
        f"{ID},{DIGEST},{LIMITS},{ID},{PURPOSE},{ID},{DIGEST},{ID},{ID}",
        API,
    ),
    (
        "veriq_recovery_enrollment(uuid,bytea,bytea,uuid,bytea,uuid,text,bytea)",
        f"{ID},{DIGEST},{DIGEST},{ID},{DIGEST},{ID},{PURPOSE},{DIGEST}",
        MFA,
    ),
    (
        "veriq_recovery_complete(uuid,bytea,bytea,bigint,bytea[],bytea[],uuid,uuid)",
        f"{ID},{DIGEST},{DIGEST},1::bigint,ARRAY[{DIGEST}],ARRAY[{DIGEST}],{ID},{ID}",
        MFA,
    ),
    (
        "veriq_recovery_reject(uuid,bytea,bytea,uuid,uuid)",
        f"{ID},{DIGEST},{DIGEST},{ID},{ID}",
        MFA,
    ),
    ("veriq_recovery_permission(uuid,uuid,text)", f"{ID},{ID},{PURPOSE}", set()),
    ("veriq_recovery_superadmin(uuid)", ID, set()),
    *tuple(
        (f"{name}({POLICY_TYPES})", POLICY_ARGS, set())
        for name in (
            "veriq_session_limits",
            "veriq_pre_recovery_session_limits",
            "veriq_base_session_limits",
        )
    ),
)


if __name__ == "__main__":
    for database in sys.argv[1:]:
        check(database, FUNCTIONS, invokers=INVOKERS)
