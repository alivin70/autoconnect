from requests import *
from AdvancedHTMLParser import *


class WifiDogCaptivePortal:

    def __init__(self):
        self.email_field_name = None
        self.password_field_name = None
        self.token_field_name = "_token"

    def try_to_connect(self):
        print("Captive portal! Trying to connect . . .")
        resp = request(method='GET', url="http://clients3.google.com/generate_204")
        cookies = resp.cookies.get_dict()
        html = resp.text
        self.find_input_fields(html)
        token = self.find_authkey(html)

        f = open("resources/credentials")
        for line in f:
            credentials = line.strip().split(",")
            username = credentials[0]
            password = credentials[1]
            print(username, password)

            data = {self.email_field_name: username, self.password_field_name: password, self.token_field_name: token}
            resp = post("http://wifidog-auth.lan/login", data=data, cookies=cookies)

            if 'These credentials do not match our records' in resp.text:
                print("Wrong username or password")
                continue

            resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
            if resp.status_code == 204:
                print("Successfully connected!")
                break
            else:
                print("Unable to connect!")
                break

    def find_input_fields(self, html_content):
        parser = AdvancedHTMLParser()
        parser.parseStr(html_content)
        form = parser.getElementsByTagName("form")
        inputs = form.getElementsByTagName("input")
        for input_field in inputs:
            if input_field.type == "email":
                self.email_field_name = input_field.name
            if input_field.type == "password":
                self.password_field_name = input_field.name

    def find_authkey(self, html_content):
        parser = AdvancedHTMLParser()
        parser.parseStr(html_content)
        authkey = parser.getElementsByName(self.token_field_name)
        if authkey is not None:
            return authkey[0].value
        else:
            return None
