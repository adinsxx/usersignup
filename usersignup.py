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

import webapp2, cgi,re, hashlib, hmac, random, string, jinja2, os

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

SECRET = 'imsosecret'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
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
        
def valid_username(username):
        return username and USER_RE.match(username)

def valid_password(password):
        return password and PASSWORD_RE.match(password)

def valid_email(email):
        return not email or EMAIL_RE.match(email)

def escape_html(s):
        return cgi.escape(s,quote = True)
   

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
class MainPage(Handler):
        def render_usersignup(self, username="", usernameerror="", passworderror="", verifyerror = "", email = "", emailerror = ""):
        
            users = db.GqlQuery("SELECT * FROM User")
            
            self.render("usersignup.html", username=username, usernameerror=usernameerror, passworderror=passworderror, verifyerror = verifyerror, email = email, emailerror = emailerror, users = users)
            
        def get(self):
                self.render_usersignup()
        
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
                
                dbUser = db.GqlQuery("SELECT * FROM User WHERE username='" + user_username + "'")
                
                if dbUser.count() and user_username == dbUser.get().username:
                        usernameerror = "User name already exists"
                
                if (not usernameerror and not passworderror and not verifyerror and not emailerror):
                    new_username_cookie_val = make_secure_val(str(user_username))
                    salted_password = make_pw_hash(user_username,user_password)
                    u = User(username = user_username, password = salted_password, email = user_email)
                    u.put()
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_username_cookie_val)
                    self.redirect("/unit2/welcome")
                else:
                    self.render_usersignup(user_username, usernameerror, passworderror, verifyerror, user_email, emailerror)

class WelcomeHandler(Handler):
        def render_welcome(self, username=""):
            self.render("welcome.html", username=username)
            
        def get(self):
            username_cookie_str = self.request.cookies.get("user_id")
            username_cookie_val = check_secure_val(username_cookie_str)
            if username_cookie_val:
                usernameCookie = username_cookie_val
                if usernameCookie:
                    self.render_welcome(usernameCookie)
                else:
                    self.redirect('/unit2/signup')
            else:
                self.redirect('/unit2/signup')
                
class LoginHandler(Handler):
        def render_login(self, loginerror=""):
            self.render("login.html", loginerror=loginerror)
            
        def get(self):
                self.render_login()
        
        def post(self):
                user_username = self.request.get('username')
                user_password = self.request.get('password')

                username = valid_username(user_username)
                password = valid_password(user_password)

                loginerror = ""
                loginerror = "" if user_username else "Invalid login"
                loginerror = "" if user_password else "Invalid login"
                loginerror = "" if username else "Invalid login"
                loginerror = "" if password else "Invalid login"
                
                dbUser = db.GqlQuery("SELECT * FROM User WHERE username='" + user_username + "'")
                
                if not dbUser.count():
                    loginerror = "Invalid login"
                else:
                    if not valid_pw(user_username, user_password, dbUser.get().password):
                        loginerror = "Invalid login"
                
                if not loginerror:
                    new_username_cookie_val = make_secure_val(str(user_username))
                    salted_password = make_pw_hash(user_username,user_password)
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_username_cookie_val)
                    self.redirect("/unit2/welcome")
                else:
                    self.render_login(loginerror)

app = webapp2.WSGIApplication([
        ('/unit2/signup', MainPage), ('/unit2/welcome', WelcomeHandler), ('/unit2/login', LoginHandler)
], debug=True)