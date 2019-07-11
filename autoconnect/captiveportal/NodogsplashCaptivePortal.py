from requests import *
from AdvancedHTMLParser import *


class NodogsplashCaptivePortal:

    def __init__(self):
        self.username_field_name = None
        self.password_field_name = None
        self.parser = AdvancedHTMLParser()
        self.tok = None
        self.redir = None
        self.authaction = None

    def try_to_connect(self):

        print("Captive portal! Trying to connect . . .")
        resp = request(method='GET', url="http://clients3.google.com/generate_204")
        html = resp.text

        self.find_input_fields(html)
        self.find_hidden_fields(html)

        url = resp.url.split("?", 1)[0]
        f = open("resources/credentials")

        for line in f:
            credentials = line.strip().split(",")
            username = credentials[0]
            password = credentials[1]
            print(username, password)

            data = {self.username_field_name: username, self.password_field_name: password, "tok": self.tok, "redir": self.redir,
                    "authaction": self.authaction}

            resp = post(url, data=data)

            html = resp.text
            if 'Invalid login attempt' in html:
                print("Wrong username or password")

            else:
                self.parser.parseStr(html)
                self.redir = self.parser.getElementsByName("redir")[0].value
                form = self.parser.getElementsByTagName("form")
                url = form[1].action
                params = {"tok": self.tok, "redir": self.redir}
                get(url, params=params)

                resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
                if resp.status_code == 204:
                    print("Successfully connected!")
                    break
                else:
                    print("Unable to connect!")
                    break

    def find_input_fields(self, html_content):
        self.parser.parseStr(html_content)
        form = self.parser.getElementsByTagName("form")
        inputs = form.getElementsByTagName("input")
        for input_field in inputs:
            if input_field.type == "text":
                self.username_field_name = input_field.name
            if input_field.type == "password":
                self.password_field_name = input_field.name

    def find_hidden_fields(self, html_content):
        self.parser.parseStr(html_content)
        self.tok = self.parser.getElementsByName("tok")[0].value
        self.redir = self.parser.getElementsByName("redir")[0].value
        self.authaction = self.parser.getElementsByName("authaction")[0].value

