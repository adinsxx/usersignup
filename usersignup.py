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

import webapp2, cgi,re, hashlib, hmac, random, string, logging, jinja2, os

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

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
            #arts = db.GqlQuery("SELECT * FROM Art "
            #                   "ORDER BY created DESC ")
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
                
                usernameCookie = ''
                #username_cookie_str = self.request.cookies.get(user_username) # handling multiple users
                username_cookie_str = self.request.cookies.get("user_id")
                logging.warning("username cookie str " + str(username_cookie_str))
                if username_cookie_str:
                    username_cookie_val = check_secure_val(username_cookie_str)
                    logging.warning("username cookie val " + str(username_cookie_val))
                    dbUser = db.GqlQuery("SELECT * FROM User WHERE username='" + user_username + "'")
                    #logging.warning("dbUser.username " + dbUser.get().username)
                    #if username_cookie_val == user_username: # added ==
                    if dbUser.count():
                        if username_cookie_val == dbUser.get().username:
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

                if (not usernameerror and not passworderror and not verifyerror and not emailerror):
                    u = User(username = user_username, password = user_password, email = user_email)
                    u.put()
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_username_cookie_val) # just for user_id
                    #self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (str(usernameCookie), new_username_cookie_val))
                    self.redirect("/unit2/welcome")
                else:
                    self.render_usersignup(user_username, usernameerror, passworderror, verifyerror, user_email, emailerror)

class WelcomeHandler(Handler):
        def render_welcome(self, username=""):
            self.render("welcome.html", username=username)
            
        def get(self):
            logging.warning("BOO " + currentCookie)
            #username_cookie_str = self.request.cookies.get(currentCookie)
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

app = webapp2.WSGIApplication([
        ('/unit2/signup', MainPage), ('/unit2/welcome', WelcomeHandler)
], debug=True)
