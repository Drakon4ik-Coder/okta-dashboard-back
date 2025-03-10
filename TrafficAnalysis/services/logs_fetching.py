import time
import jwt
import requests
import uuid
import schedule



okta_domain = "https://dev-27051270.okta.com/"
token_endpoint = okta_domain + "oauth2/v1/token"
client_id = "0oanklbwmwvsPqp5M5d7"
client_secret = "WrB9f-1Zlo_iDQjbN2gI_BGjiP1jKJnPMAp88R3Vv92fFnVs3N2U7ITTyzzbMboZ"
kid = "e7eP5nwiDaYgqdD-FGWvAVNrlMchsUSZbGXzCjamAYA"


private_key = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5ZNy4Ux4oDig+
EGwmhlr9ntKLH7uQ2cXMyTYMKwhpfMSXBCbuUzpllqRzSdGjkqj1wpESsrZGRJ9D
a0bRaea1ZMG9eGb8/9hZCDF2Ny4SjSLr4wSCiI3YdXwcMykC+x7cZkJ8zSrt5tVQ
jWlDksGD4O9/CRJwEKk+XMIT+/bff+YOZpeH2oFsRZdksvytgiIFFhAGRpMozM8C
P+9UgqDr9ei1bmRiin8U5SLxmzQt6+8ITVBqO5DR+6X2piMf4twOM013p6gpjydt
D18EnizBk+cEA4MxAnGzKyBf/bqY93AuxNTBtCNsGs8Dq7xLouC8sRk6X+/H/dnG
k4WlISrNAgMBAAECggEAAuuE4R3lIpaYRePBN26QhvzEStYBVg9isQ5c6uV6nf64
ateb5kEOOGhJACGiLotdBzySY+9ybiwChUUZSDnD5EG7Hh5nlGluvcvNPWlrTXYq
SKRlKgLwlzhrYZAaDe2+LLErL84/5i4D5ooB3qbQ3QP/ga3TkS71jTqROjNZ+LyC
/f+wI+km/nXxQvT7OC1O2TjcEs37bO6yks4TtJc85eX91Ot25sQExFvUVQzlIFN3
58ZF50qstuvpTiGt2ffI+MsGvk5sLWBMEgouhsWbMRwlhfC05/lh+CWtadDMWOzA
YFB0tBhavL4d2pIw5enFSjzucYh5BNdzv9AUtgatmQKBgQDbb+r6DvHlLgup4smD
r+I7n/CY3PMbf+MoiVHMkKTBh05QJNTdwm2+IZNiCHFITFGquigy46jbUeOnrh0m
HV3YWznChRISqFvOzyEoKc3Ug2Kb3F+I3IS+3f1Pq7e27+6NkVKFhf6ELe0drGYa
ITk5/HqkXZL+sBTFCrf1a5v2awKBgQDYSNV4UL3ImETotcSrIcIXXozPz7LPnSSi
L8ycWBtzT2+c6cgkBrmcbVtkbvMKRsC7wfLES5/E7APgPHESz9nEAqstQW/8ueeJ
o5mHzLokpRZaA4oj79aOBgqm45An8DBMjbLCgNWaArhf4O7oMEEQuyR8aHM/ByZG
dnUWrIcBpwKBgDng7TODmZ3/ZSgsH0bSr3NWnllTffP06W+ZuK+iPzKkg61z6YmM
bPHHXV5wJ6EQMEI907iIf9NJaCikLiANguE8PqHmA3xUV9LWo0I6tIWnGe1OVQx+
Ta0iVFwdSNnBs0Q33nJFg3pNussm289sj/GRfK+51rnCq9fFGfxro7l9AoGBAKBn
A8pDNzz5kMF1bPHuC2ABgzTruJU42d5ezMR2o4UVOJWK3B+7zRQyFkGZ9y1745xb
7oud+lO1Jfq7WLC27a3svL7HdSJdTVZKuqZ4MuTSeo0vatfUG68g0+2Jf3PfMjLU
M+sEWWXq9opE62nPv7GE2T5ayH3J85z2ZUf3k/ipAoGBAMjIkmRGrXaGzg1JxTNl
qT0qTm9naCD7MLjVMDtRj2bIez9K8oghpAQv0OzirOuUrrBVuT+p5fB6tFJn/X8A
wV0rdeqOzjdZvbGJXG7aX8JoUuvgTD+EuYmH7tRE2cZLRAuIXPGf6LD0pf1myPuN
h2DI9zZ1r+h9QZkrJniVW6xn
-----END PRIVATE KEY-----
"""
current_time = int(time.time())

# Define the API endpoint
logs_endpoint = f"{okta_domain}/api/v1/logs"


# Update to use current_time
dpop_jwt_payload = {
    "iat": current_time,
    "exp": current_time + 300,
    "jti": str(uuid.uuid4()),
    "htm": "POST",
    "htu": token_endpoint
}

dpop_jwt_header = {
    "alg": "RS256",
    "kid": "e7eP5nwiDaYgqdD-FGWvAVNrlMchsUSZbGXzCjamAYA",
    "typ": "dpop+jwt"
}

dpop_jwt = jwt.encode(
    dpop_jwt_payload,
    private_key,
    algorithm="RS256",
    headers=dpop_jwt_header
)

# Update client assertion payload to use current_time
client_assertion_payload = {
    "iat": current_time,
    "iss": client_id,
    "sub": client_id,
    "aud": token_endpoint,
    "exp": current_time + 300  # 1 hour expiration
}

# Encode the client assertion JWT
client_assertion_jwt = jwt.encode(
    client_assertion_payload,
    private_key,
    algorithm="RS256",
    headers={"alg": "RS256", "typ": "JWT", "kid": kid}
)

print("DPoP JWT:", dpop_jwt)
print("Client Assertion JWT:", client_assertion_jwt)

# Data and headers for token request
data = {
    "grant_type": "client_credentials",
    "scope": "okta.logs.read",
    "client_assertion": client_assertion_jwt,
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
}

headers = {
    "DPoP": dpop_jwt,
    "Content-Type": "application/x-www-form-urlencoded"
}

# Make the request
try:
    response = requests.post(token_endpoint, data=data, headers=headers)
    response.raise_for_status()
    access_token = response.json().get("access_token")
    print(f"Access Token: {access_token}")

except requests.exceptions.RequestException as e:
    print(f"Error getting access token: {response.status_code if 'response' in locals() else 'No response'}")
    print(f"Error details: {e}")
    if 'response' in locals():
        print(f"Response text: {response.text}")
    access_token = None
def fetch_logs(access_token):
    if not access_token:
        print("There is no valid access token")
        return None

    logs_endpoint = f"{okta_domain}api/v1/logs"

    logs_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    # Optional query parameters to filter logs (adjust as needed)
    params = {
        "since": "2025-03-01T00:00:00.000Z",  # ISO 8601 format timestamp
        "until": "2025-03-05T23:59:59.000Z",  # Up to current date
        "limit": 100,  # Number of log entries per page (max 1000)
        # Add other filters as needed: q, filter, sortOrder
    }


    try:
        response_logs = requests.get(logs_endpoint, headers=logs_headers, params=params)
        response_logs.raise_for_status()

        logs = response_logs.json()


        print("System Logs:")
        for log_entry in logs:
            print(f"Time: {log_entry.get('published')}")
            print(f"Event Type: {log_entry.get('eventType')}")
            print(f"Actor: {log_entry.get('actor', {}).get('displayName', 'N/A')}")
            print(f"Outcome: {log_entry.get('outcome', {}).get('result', 'N/A')}")
            print("---")


        # Handle pagination if needed
        next_link = response_logs.headers.get('Link', '').split(';')[0].strip('<>')
        if next_link:
            print("More logs available at:", next_link)

        return logs

    except requests.exceptions.RequestException as e:
        print(f"Error getting logs: {response_logs.status_code if 'response_logs' in locals() else 'No response'}")
        print(f"Error details: {e}")
        if 'response_logs' in locals():
            print(f"Response text: {response_logs.text}")
        return None

# Call the function with the access_token
if access_token:
    logs = fetch_logs(access_token)
else:
    print("Cannot fetch logs without access token")
def scheduler_task():
    if access_token:
        fetch_logs(access_token)


# Schedule to run every 10 minutes
schedule.every(10).minutes.do(scheduler_task)

while True:

    schedule.run_pending()
    time.sleep(1)









