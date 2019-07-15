from requests import *
from captiveportal.CaptivePortalHandler import CaptivePortalHandler


class WifiDogCaptivePortal(CaptivePortalHandler):

    def __init__(self):
        CaptivePortalHandler.__init__(self, "email", "_token")

    def try_to_connect(self):
        resp = request(method='GET', url="http://clients3.google.com/generate_204")
        cookies = resp.cookies.get_dict()
        html = resp.text
        input_exist = self.find_input_fields(html)
        token = self.find_token(html)

        if input_exist and token is not None:
            url = resp.url.split("?", 1)[0]
            f = open("resources/credentials")

            for line in f:
                credentials = line.strip().split(",")
                username = credentials[0]
                password = credentials[1]
                print(username, password)

                data = {self.username_field_name: username, self.password_field_name: password, self.token_field_name: token}
                resp = post(url, data=data, cookies=cookies)

                if 'These credentials do not match our records' in resp.text:
                    print("Wrong username or password")
                    continue

                resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
                if resp.status_code == 204:
                    print("Successfully connected!")
                    return True
                else:
                    print("Unable to connect!")
                    return False
        else:
            print("Unable to connect!")
            return False
