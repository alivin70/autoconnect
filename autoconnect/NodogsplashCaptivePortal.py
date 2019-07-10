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
        data = {self.username_field_name: "dick", self.password_field_name: "123456", "tok": self.tok, "redir": self.redir,
                "authaction": self.authaction}

        url = resp.url.split("?", 1)[0]
        resp = post(url, data=data)

        html = resp.text
        self.parser.parseStr(html)
        self.redir = self.parser.getElementsByName("redir")[0].value
        form = self.parser.getElementsByTagName("form")
        url = form[1].action
        params = {"tok": self.tok, "redir": self.redir}
        resp = get(url, params=params)

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

