import os
import re
import random
import hashlib
import hmac
import json
import datetime

import webapp2
import jinja2

from string import letters
from google.appengine.ext import db

web_dir = os.path.join(os.path.dirname(__file__), 'web')
JINJA_ENVIRONMENT = jinja2.Environment(loader = jinja2.FileSystemLoader(web_dir), autoescape=True)

secret = 'secret'

def render_str(template, **params):
    t = JINJA_ENVIRONMENT.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(MainHandler):
  def get(self):
      self.redirect('/blog')

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class PostDB(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self, key = str(self.key()))
		
	def toJson(self):
		POST_TYPES = (str, str, datetime.date,datetime.date)
		output = {}
		for key in self.properties():
			value = getattr(self, key)
			if isinstance(value, datetime.date):
				dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime.datetime) else None
				output[key] = json.dumps(value, default=dthandler)
			elif isinstance(value, str):
				output[key] = value
			elif isinstance(value, unicode):
				output[key] = value.decode('unicode-escape')
			elif isinstance(value, db.Model):
				output[key] = to_dict(value)
			else:
				raise ValueError('cannot encode ' + repr(value))
		return output

class Blog(MainHandler):
    def get(self):
        posts = db.GqlQuery("select * from PostDB order by created desc limit 10")
        self.render('front.html', posts = posts)

class Post(MainHandler):
	def get(self):
		key = self.request.get('id')
		post = db.get(key)
		
		if not post:
			self.redirect('/blog')
			return 
			
		self.render("permalink.html", post = post)
		
class PostJson(MainHandler):
	def get(self):
		key = self.request.get('id')
		post = db.get(key)
		
		if not post:
			self.redirect('/blog')
			return

		self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
		self.write(json.dumps(post.toJson()))

class BlogJson(MainHandler):
    def get(self):
        articles = db.GqlQuery('SELECT * FROM PostDB '
                               'ORDER BY created DESC '
                               'LIMIT 20')
        content = [{'subject': article.subject,
                    'content': article.content,
                    'created': str(article.created.strftime('%a %b %d %H:%M:%S %Y')),
                    'last_modified': str(article.last_modified.strftime('%a %b %d %H:%M:%S %Y'))
                   } for article in articles]
        self.response.headers['Content-Type'] = 'application/json'
        self.write(json.dumps(content, indent=4))

class NewPost(MainHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = PostDB(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog')
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class Signup(MainHandler):
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	PASS_RE = re.compile(r"^.{3,20}$")
	EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
	username = ''
	email = ''
	password = ''

	def valid_username(self, username):
		return username and self.USER_RE.match(username)

	def valid_password(self, password):
		return password and self.PASS_RE.match(password)

	def valid_email(self, email):
		return not email or self.EMAIL_RE.match(email)
	
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')		
		self.password = self.request.get('password')
		verify = self.request.get('verify')
		self.email = self.request.get('email')
		
		params = dict(username = self.username, email = self.email)
		
		if not self.valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		
		if not self.valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password !=verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True
		
		if not self.valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(MainHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog', Blog),
                               ('/blogpost', Post),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog.json', BlogJson),
                               ('/blog/.json', BlogJson),
                               ('/blog/([0-9]+).json', PostJson),
                               ],
                              debug=True)
