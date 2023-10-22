#!/usr/bin/env python3

import base64
import time
import sys
import requests
import json
import os

from jwt import JWT, jwk_from_pem

GH_API_CALL_ATTEMPTS = 10
PEM_DATA_B64 = os.environ['PEM_B64']
PEM_DATA_ASCII = PEM_DATA_B64.encode("ascii")
convertedbytes = base64.b64decode(PEM_DATA_ASCII)
signing_key = jwk_from_pem(convertedbytes)

GH_APP_ID = os.environ['GH_APP_ID']
GH_APP_INSTALLATION_ID = os.environ['GH_APP_INSTALLATION_ID']

payload = {
    # Issued at time
    'iat': int(time.time()),
    # JWT expiration time (10 minutes maximum)
    'exp': int(time.time()) + 600,
    # GitHub App's identifier
    'iss': GH_APP_ID
}

jwt_instance = JWT()
encoded_jwt = jwt_instance.encode(payload, signing_key, alg='RS256')

headers = {"Authorization": f"Bearer {encoded_jwt}",
           "Accept": "application/vnd.github+json",
           "X-GitHub-Api-Version": "2022-11-28"
           }
url = f"https://api.github.com/app/installations/{GH_APP_INSTALLATION_ID}/access_tokens"

for i in range(1,GH_API_CALL_ATTEMPTS):
    r = requests.post(url, headers=headers)
    if r.status_code != 201 and i == GH_API_CALL_ATTEMPTS - 1:
        raise IOError(f"GH API call returns {r.status_code}. Find more here: https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app")
    elif r.status_code != 201 and i < GH_API_CALL_ATTEMPTS - 1:
        print(f"Attempt {i} returned error: {r.status_code}")
        time.sleep(1)
    else:
        response_json = r.json()
        access_token = response_json['token']

        # token tests
        assert len(access_token) == 40, "Test of token length: failure."
        assert access_token.startswith("ghs_"), "Wrong token preffix."

        # Set output
        GITHUB_OUTPUT_FILE = os.environ['GITHUB_OUTPUT']

        with open(GITHUB_OUTPUT_FILE, 'a') as fd:
          fd.write(f"GH_ACCESS_TOKEN={access_token}")

        break
