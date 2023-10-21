#!/usr/bin/env python
import os

if __name__ == '__main__':
    access_token = os.environ['ACCESS_TOKEN']
    assert len(access_token) == 40, "Test of token length: failure."
    assert access_token.startswith("ghs_"), "Wrong token preffix."
