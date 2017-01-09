# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2, cgi,re, hashlib, hmac, random, string, logging

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

SECRET = 'imsosecret'

global currentCookie

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    logging.warning("What is hash_str(s) " + hash_str(s))
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    #logging.warning("what is h " + h)
    val = h.split('|')[0]
    #logging.warning("what is val " + val)
    if h == make_secure_val(val):
        return val
                
def make_salt():
        valid_letters='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        return ''.join((random.choice(valid_letters) for i in xrange(5)))

def make_pw_hash(name, pw, salt = None):
        if not salt:
                salt = make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
        salt = h.split(',')[1]
        return h == make_pw_hash(name, pw, salt)

form="""
<!DOCTYPE html>
<html>
<head><title>Sign Up</title></head>
<body>
<h2>Sign Up</h2>
<form method="post">    
        <table>
                <tr>
                    <td class="label">
                        Username
                    </td>
                    <td>
                        <input type="text" name="username" value="%(username)s">
                    </td>
                    <td>
                        <div style="color: red">%(usernameerror)s</div>
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Password
                    </td>
                    <td>
                        <input type="password" name="password" value="">
                    </td>
                    <td>
                        <div style="color: red">%(passworderror)s</div>
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Verify Password
                    </td>
                    <td>
                        <input type="password" name="verify" value="">
                    </td>
                    <td>
                        <div style="color: red">%(verifyerror)s</div>
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Email (optional)
                    </td>
                    <td>
                        <input type="text" name="email" value="%(email)s">
                    </td>
                    <td>
                        <div style="color: red">%(emailerror)s</div>
                    </td>
                </tr>
        </table>
        <br>
        <input type="submit"> 
</form>
</body>
</html>
"""

def valid_username(username):
        return username and USER_RE.match(username)

def valid_password(password):
        return password and PASSWORD_RE.match(password)

def valid_email(email):
        return not email or EMAIL_RE.match(email)

def escape_html(s):
        return cgi.escape(s,quote = True)

class MainPage(webapp2.RequestHandler):
        def write_form(self, usernameerror="", passworderror="", verifyerror="", emailerror="", username="", email=""):
                self.response.out.write(form % {"usernameerror": usernameerror,
                        "passworderror": passworderror,
                        "verifyerror": verifyerror,
                        "emailerror": emailerror,
                        "username": escape_html(username),
                        "email": escape_html(email)})
        
        def get(self):
                self.write_form()
        
        def post(self):
                user_username = self.request.get('username')
                user_password = self.request.get('password')
                user_verify = self.request.get('verify')
                user_email = self.request.get ('email')

                username = valid_username(user_username)
                password = valid_password(user_password)
                verify = valid_password(user_verify)
                email = valid_email(user_email) if user_email else 'true'

                usernameerror = "" if username else "That's not a valid username."
                passworderror = "" if password else "That wasn't a valid password."
                verifyerror = "" if passworderror else "" if user_password == user_verify else "Your passwords didnt match."
                emailerror = "" if email else "That's not a valid email."
                
                usernameCookie = ''
                #username_cookie_str = self.request.cookies.get(user_username) # handling multiple users
                username_cookie_str = self.request.cookies.get("user_id")
                logging.warning("username cookie str " + str(username_cookie_str))
                if username_cookie_str:
                    username_cookie_val = check_secure_val(username_cookie_str)
                    logging.warning("username cookie val " + str(username_cookie_val))
                    if username_cookie_val == user_username: # added ==
                        usernameCookie = username_cookie_val
                        logging.warning("usernameCookie " + str(usernameCookie))
                        usernameerror = "User name already exists"
                    else:
                        logging.warning("else")
                        usernameCookie = user_username # added
                else:
                    usernameCookie = user_username

                new_username_cookie_val = make_secure_val(str(usernameCookie))
                global currentCookie
                currentCookie = str(usernameCookie)
                #self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (str(usernameCookie), new_username_cookie_val))


                if (not usernameerror and not passworderror and not verifyerror and not emailerror):
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_username_cookie_val) # just for user_id
                    self.redirect("/unit2/welcome")
                else:
                    self.write_form(usernameerror, passworderror, verifyerror, emailerror, user_username, user_email)

class WelcomeHandler(webapp2.RequestHandler):
        def get(self):
            logging.warning("BOO " + currentCookie)
            #username_cookie_str = self.request.cookies.get(currentCookie)
            username_cookie_str = self.request.cookies.get("user_id")
            username_cookie_val = check_secure_val(username_cookie_str)
            if username_cookie_val:
                usernameCookie = username_cookie_val
                if usernameCookie:
                    self.response.out.write("<!DOCTYPE html><html><head><title>Unit 2 Signup</title></head><body><h2>Welcome, " + usernameCookie + "!</h2></body></html>")
                else:
                    self.redirect('/unit2/signup')
            else:
                self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([
        ('/unit2/signup', MainPage), ('/unit2/welcome', WelcomeHandler)
], debug=True)
