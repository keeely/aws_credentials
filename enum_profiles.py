#!/usr/bin/env python3
"""
    Demonstration of how to obtain credentials for all profiles using the SSO browser cookie
    Requires you to have signed on to AWS first via the browser, ideally logging on to one of your 
    accounts.
    
    Note that this enumeration requires no 'starter' account to bootstrap it you just need the cookie.
    You may get an OS prompt when the Python script attempts to decrypt the cookie, you have to accept it
    to continue.
    
    It's not recommended to use this in production as a more secure way of accessing your accounts would
    be to use aws sso login from the command-line, and create the necessary ~/.aws/config file to manage
    different profiles without storing the credentials, but this is just to show what's currently possible.
    
    To run, obtain parameters from your normal SSO profile, e.g suppose you had in ~/.aws/config:

        [profile myprofile]
        sso_start_url = https://d-0123456789.awsapps.com/start#/
        sso_region = us-east-1
        
    Then you would execute with with:
    
    ./enum_profiles.py -u https://d-0123456789.awsapps.com/start#/ -r us-east-1
    
    The output of the script can be sent to ~/.aws/credentials
 
    Requires browser_cookie3:  pip3 install browser-cookie3
"""


import sys
import browser_cookie3
import requests
from argparse import ArgumentParser
from urllib.parse import urlparse
from datetime import datetime


def get_auth(start_url):
    url = urlparse(start_url)
    cookie_jar = browser_cookie3.chrome(domain_name=url.hostname)
    for cookie in list(iter(cookie_jar)):
        if cookie.domain == url.hostname and cookie.name == "x-amz-sso_authn":
            expiry_time = datetime.fromtimestamp(cookie.expires)
            now = datetime.now()
            if now < expiry_time:
                now = now.isoformat(timespec='seconds', sep=' ')
                print(f"# Found x-amz-sso_authn cookie for {url.hostname}, expires {expiry_time}, it's now {now}")
                return cookie.value
    sys.exit("Unable to find cookie")


def get_headers(portal, auth):
    return {
        "pragma": "no-cache",
        'authority': portal,
        'accept': 'application/json, text/plain, */*',
        'x-amz-sso_bearer_token': auth,
        'x-amz-sso-bearer-token': auth
    }


def enum_accounts(headers, portal):
    response = requests.get(f"https://{portal}/instance/appinstances", headers=headers)
    if response.status_code == 401:
        sys.exit("Cookie has probably expired.")
    if response.status_code != 200:
        sys.exit("Error enumerating AWS accounts")

    result = response.json()["result"]
    return result


def get_account_profiles(headers, portal, ins_id):
    response = requests.get(f"https://{portal}/instance/appinstance/{ins_id}/profiles", headers=headers)
    return response.json()["result"]


def get_account_credentials(headers, portal,  account_id, role):
    response = requests.get(f"https://{portal}/federation/credentials",
                            params={"account_id": account_id, "role_name": role, "debug": "true"},
                            headers=headers)
    return response.json()["roleCredentials"]


profile_template = """# %(description)s
[%(account_id)s_%(role)s]
aws_access_key_id = %(accessKeyId)s
aws_secret_access_key = %(secretAccessKey)s
aws_session_token = %(sessionToken)s
"""


def create_profile(account_id, role, creds, description):
    args = {"account_id": account_id, "role": role, "description": description}
    args.update(creds)
    return profile_template % args


def check_args():
    parser = ArgumentParser(prog='enum_profiles')
    parser.add_argument("-u", "--ssostarturl", help="sso_start_url, from ~/.aws/config", required=True)
    parser.add_argument("-r", "--ssoregion", help="sso_region, from ~/.aws/config", required=True)
    return parser


def main():
    parser = check_args()    
    args = parser.parse_args()
    auth = get_auth(args.ssostarturl)
    portal = f"portal.sso.{args.ssoregion}.amazonaws.com"
    headers = get_headers(portal, auth)

    for account in enum_accounts(headers, portal):
        account_id = account["searchMetadata"]["AccountId"]
        ins_id = account["id"]
        profiles = get_account_profiles(headers, portal, ins_id)
        description = account["name"]
        for profile in profiles:
            role = profile["name"]
            creds = get_account_credentials(headers, portal, account_id, role)
            txt = create_profile(account_id, role, creds, description)
            print(txt)


if __name__ == "__main__":
    main()
