from abc import ABC, abstractmethod
from AdvancedHTMLParser import *


class CaptivePortalHandler (ABC):

    def __init__(self, username_type, token_field_name):
        self.username_field_name = None
        self.password_field_name = None
        self.parser = AdvancedHTMLParser()
        self.username_type = username_type
        self.token_field_name = token_field_name

    @abstractmethod
    def try_to_connect(self):
        pass

    def find_input_fields(self, html_content):
        self.parser.parseStr(html_content)
        form = self.parser.getElementsByTagName("form")
        inputs = form.getElementsByTagName("input")
        for input_field in inputs:
            if input_field.type == self.username_type:
                self.username_field_name = input_field.name
            if input_field.type == "password":
                self.password_field_name = input_field.name

        if self.username_field_name is not None and self.password_field_name is not None:
            return True
        else:
            return False

    def find_token(self, html_content):
        self.parser.parseStr(html_content)
        token = self.parser.getElementsByName(self.token_field_name)
        if len(token) > 0:
            return token[0].value
        else:
            return None
