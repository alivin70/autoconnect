from requests import *
from html.parser import HTMLParser
from AdvancedHTMLParser import *


class ZSParser(HTMLParser):
    def __init__(self, url, username, password, realm, zscp_redirect):
        HTMLParser.__init__(self)
        self.params = {}
        params = {'U': username, 'P': password, 'Realm': realm, 'Section': 'CPAuth', 'Action': 'Authenticate',
                  'ZSCPRedirect': zscp_redirect}
        resp = get(url, params=params)
        html_content = resp.text
        self.feed(html_content)

    def get_authkey(self):
        if 'Authenticator' in self.params:
            # after parse HTML return the authenticator string
            return self.params['Authenticator']
        else:
            return None

    def handle_starttag(self, tag, attrs):
        # parse only de html input and hidden tags
        if tag == 'input' and attrs[0][1] == 'hidden':
            self.params[attrs[1][1]] = attrs[2][1]


class CaptivePortalHandler:

    def __init__(self):
        pass

    def try_to_connect(self):
        print("Captive portal! Trying to connect . . .")
        resp = request(method='GET', url="http://clients3.google.com/generate_204")

        parser = AdvancedHTMLParser()
        parser.parseStr(resp.text)
        form = parser.getElementsByTagName("form")
        inputs = form.getElementsByTagName("input")
        for input_field in inputs:
            print(input_field)

        # TODO find name of the input fields (username, password)

        # url = resp.url.split("?", 1)[0]
        #
        # username = "admin"
        # password = "zeroshell"
        # realm = "example.com"
        # zscp_redirect = "_:::_"
        # renew_interval = 40
        #
        # parser = ZSParser(url, username, password, realm, zscp_redirect)  # instantiate the class
        # authkey = parser.get_authkey()  # get authenticator string
        #
        # if authkey is not None:
        #     params = {'U': username, 'P': password, 'Realm': realm, 'Authenticator': authkey, 'Section': 'CPGW',
        #               'Action': 'Connect', 'ZSCPRedirect': zscp_redirect}
        #     resp = get(url, params=params)
        #     print(resp.status_code)
        #
        #     params = {'U': username, 'P': password, 'Realm': realm, 'Authenticator': authkey, 'Section': 'ClientCTRL',
        #               'Action': 'Connect', 'ZSCPRedirect': zscp_redirect}
        #     resp = get(url, params=params)
        #     print(resp.status_code)
        #
        #     resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
        #     if resp.status_code == 204:
        #         print("Successfully connected!")
        #     else:
        #         print("Unable to connect!")
        # else:
        #     print("No authentication key")