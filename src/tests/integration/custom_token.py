import jwt
import os

from datetime import datetime, timezone, timedelta


def get_authorization_header(testcase_specific_payload, token_algorithm="RS256"):
    payload = {
        "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=10),
        "iss": str(os.getenv("STATIC_ISSUER")),
        "sub": str(os.getenv("STATIC_ISSUER")),
    }

    private_key = f"-----BEGIN PRIVATE KEY-----\n{os.getenv('STATIC_PRIVATE_KEY')}\n-----END PRIVATE KEY-----"
    testcase_specific_payload.update(payload)

    token = jwt.encode(
        testcase_specific_payload, private_key, algorithm=token_algorithm
    )
    return {"Authorization": f"Bearer {token}"}
