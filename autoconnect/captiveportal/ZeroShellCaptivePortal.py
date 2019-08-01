from requests import *
from captiveportal.CaptivePortalHandler import CaptivePortalHandler


class ZeroShellCaptivePortal(CaptivePortalHandler):
    """
    A class used to handle the presence of ZeroShell Captive Portal

    Attributes
    ----------
    domain_name : str
        the name of the HTML select field for the domains
    domains : str
        the values of the HTML select field for the domains

    Methods
    -------
    try_to_connect()
        Tries to authenticate to the ZeroShell Captive Portal
    find_input_fields()
        Tries to find username, password and domain HTML elements parsing the HTML page and searching for input fields within forms
    """

    def __init__(self, credentials_file):
        CaptivePortalHandler.__init__(self, "text", "Authenticator", credentials_file)
        self.domain_name = None
        self.domains = []

    def try_to_connect(self):
        """
        Tries to authenticate to the ZeroShell Captive Portal

        Returns
        -------
        returns True if the authentication was successful with some provided username and password
        returns False otherwise
        """
        resp = request(method='GET', url="http://clients3.google.com/generate_204")
        html = resp.text
        input_exist = self.find_input_fields(html)
        if input_exist:
            url = resp.url.split("?", 1)[0]
            if self.credentials_file is not None:
                f = open(self.credentials_file)
                # Tries the provided username and password for every domain
                for domain in self.domains:
                    for line in f:
                        credentials = line.strip().split(",")
                        username = credentials[0]
                        password = credentials[1]
                        realm = domain
                        zscp_redirect = "_:::_"
                        print(username, password, realm)

                        params = {self.username_field_name: username, self.password_field_name: password, self.domain_name: realm,
                                  'Section': 'CPAuth', 'Action': 'Authenticate', 'ZSCPRedirect': zscp_redirect}
                        resp = get(url, params=params)
                        html = resp.text

                        if 'Access Denied' in html:
                            print("Wrong username or password")

                        else:
                            authkey = self.find_token(html)
                            if authkey is not None:
                                params = {self.username_field_name: username, self.password_field_name: password, self.domain_name: realm,
                                          'Authenticator': authkey, 'Section': 'CPGW', 'Action': 'Connect', 'ZSCPRedirect': zscp_redirect}
                                resp = get(url, params=params)

                                params = {self.username_field_name: username, self.password_field_name: password, self.domain_name: realm,
                                          'Authenticator': authkey, 'Section': 'ClientCTRL', 'Action': 'Connect',
                                          'ZSCPRedirect': zscp_redirect}
                                resp = get(url, params=params)

                                resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
                                if resp.status_code == 204:
                                    print("Successfully connected!")
                                    return True
                                else:
                                    print("Unable to connect!")
                                    return False
                            else:
                                print("No authentication key")

                print("Unable to connect! No credentials gained access!")
                return False
            else:
                print("Unable to connect! You need to provide a csv credentials file!")
                return False

        else:
            print("Unable to connect!")
            return False

    def find_input_fields(self, html_content):
        """
        Tries to find username, password and domain HTML elements parsing the HTML page and searching for input fields within forms

        Parameters
        ---------
        html_content : str
            the content of the HTML page

        Returns
        -------
            returns True if all the elements were founded
            returns False otherwise
        """
        found = CaptivePortalHandler.find_input_fields(self, html_content)
        form = self.parser.getElementsByTagName("form")
        tag_collection = form.getElementsByTagName("select")
        if len(tag_collection) > 0:
            select = tag_collection[0]
            self.domain_name = select.name
            for option in select:
                self.domains.append(option.value)
        return found and self.domain_name is not None
