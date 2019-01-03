
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
    
    # Split the issuers to { issuer: path }
    issuer_dict = {}
    for issuer in issuers:
        split_issuers = issuer.split(";", 1)
        if len(split_issuers) == 1:
            issuer_dict[issuer] = "/"
        else:
            issuer_dict[split_issuers[0]] = split_issuers[1]
    
    sys.stderr.write(str(issuer_dict) + "\n")

    # Get the token, and make sure the issuer is one that we trust
    token = token_file.read()

    # Get the unverified token so we can check the issuer
    unverified_token = jwt.decode(token, verify=False)
    if 'iss' not in unverified_token:
        return False

    if unverified_token['iss'] not in issuer_dict:
        return False

    # Validate the token
    # How to get the audience?
    token = scitokens.SciToken.deserialize(token, audience = "ANY")

    enforcer = scitokens.Enforcer(token['iss'])
    test_path = issuer_dict[token['iss']]
    enforcer.test(token, "read:" + test_path)

    return True