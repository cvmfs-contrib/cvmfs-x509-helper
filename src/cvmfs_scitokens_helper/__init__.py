
import sys
import scitokens
import jwt

def check_token(membership, token_file):

    # Get the allowed issuers
    # Loop through the membership, looking for issuers
    issuers = []
    for line in membership.split('\n'):
        if line.startswith("https"):
            issuers.append(line)

    # Get the token, and make sure the issuer is one that we trust
    token = token_file.read()

    # Get the unverified token so we can check the issuer
    unverified_token = jwt.decode(token, verify=False)
    if 'iss' not in unverified_token:
        return False

    if unverified_token['iss'] not in issuers:
        return False

    # Validate the token
    # How to get the audience?
    token = scitokens.SciToken.deserialize(token, audience = "CVMFS")

    return True