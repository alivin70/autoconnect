from requests import *
from AdvancedHTMLParser import *


class ZeroShellCaptivePortal:

    def __init__(self):
        self.username_field_name = None
        self.password_field_name = None
        self.parser = AdvancedHTMLParser()
        self.domain_name = None
        self.domains = []

    def try_to_connect(self):
        print("Captive portal! Trying to connect . . .")
        resp = request(method='GET', url="http://clients3.google.com/generate_204")

        self.find_input_fields(resp.text)

        url = resp.url.split("?", 1)[0]

        f = open("resources/credentials")

        for domain in self.domains:
            for line in f:
                credentials = line.strip().split(",")
                username = credentials[0]
                password = credentials[1]
                realm = domain
                zscp_redirect = "_:::_"
                print(username, password, realm)

                params = {self.username_field_name: username, self.password_field_name: password, self.domain_name: realm, 'Section': 'CPAuth',
                          'Action': 'Authenticate', 'ZSCPRedirect': zscp_redirect}
                resp = get(url, params=params)
                html = resp.text

                if 'Access Denied' in html:
                    print("Wrong username or password")

                else:
                    authkey = self.find_authkey(html)
                    if authkey is not None:
                        params = {self.username_field_name: username, self.password_field_name: password, self.domain_name: realm,
                                  'Authenticator': authkey, 'Section': 'CPGW', 'Action': 'Connect', 'ZSCPRedirect': zscp_redirect}
                        resp = get(url, params=params)
                        print(resp.status_code)

                        params = {self.username_field_name: username, self.password_field_name: password, self.domain_name: realm,
                                  'Authenticator': authkey, 'Section': 'ClientCTRL', 'Action': 'Connect',
                                  'ZSCPRedirect': zscp_redirect}
                        resp = get(url, params=params)
                        print(resp.status_code)

                        resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
                        if resp.status_code == 204:
                            print("Successfully connected!")
                            return
                        else:
                            print("Unable to connect!")
                    else:
                        print("No authentication key")

    def find_input_fields(self, html_content):
        self.parser.parseStr(html_content)
        form = self.parser.getElementsByTagName("form")
        inputs = form.getElementsByTagName("input")
        for input_field in inputs:
            if input_field.type == "text":
                self.username_field_name = input_field.name
            if input_field.type == "password":
                self.password_field_name = input_field.name

        select = form.getElementsByTagName("select")
        self.domain_name = select[0].name
        for option in select[0]:
            self.domains.append(option.value)

    def find_authkey(self, html_content):
        self.parser.parseStr(html_content)
        authkey = self.parser.getElementsByName("Authenticator")
        if authkey is not None:
            return authkey[0].value
        else:
            return None
