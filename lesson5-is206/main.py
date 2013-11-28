import os
import re
import random
import hashlib
import hmac
import json
import datetime
import string

import webapp2
import jinja2

from string import letters
from google.appengine.ext import db

#the template handlings
web_dir = os.path.join(os.path.dirname(__file__), 'web')
JINJA_ENVIRONMENT = jinja2.Environment(loader = jinja2.FileSystemLoader(web_dir), autoescape=True)

secret = 'secret'	#the secret for the hashing

def render_str(template, **params):
    t = JINJA_ENVIRONMENT.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#This is the main handler, and the mother class of many of the classes
#in this code.
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

#
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#The handler of root. When / URL is entered, index.html is rendered.
class MainPage(MainHandler):
  def get(self):
      self.render('index.html')

#
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

#
def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

#
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#this class contains the user database, and is a subclass of Google's 
#db.Model.
class User(db.Model):
    #each user will have these fields, and they are given a type.
	#field = type (restrictions)
	name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

	#fetches the user by the given id in uid. ...
    @classmethod # ...
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

	#fetches the user by the given name. Then it filters it by  ... 
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

	#when this function is called, it makes a hash out of the password
	#by calling the make_pw_hask function. 
	#Then it returns the user-object. ....
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

#this function is not connected to a class. It returns the key of the
#blog.
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#this class contains the post database, and is a subclass of Google's 
#db.Model.
class PostDB(db.Model):
	#each post will have these fields, and they are given a type.
	#field = type (restrictions)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	#...
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self, key = str(self.key()))

	#...
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

#if the /blog url is entred, this handler will be used. It fetches all
#the posts from the database, puts it in the posts variable and renders
#it all to the front.html-page
class Blog(MainHandler):
    def get(self):
        posts = db.GqlQuery("select * from PostDB order by created desc limit 10")
        self.render('front.html', posts = posts)

#If a user was to look at one single post, the /blogpost URL is entered
#and the requst is handled by this handler.
class Post(MainHandler):
	#the id from the url is collected and put in the variable key. Then
	#if the user entered the .json at the end of the url instead of
	#right after /blogpost, the json_redirect is called and the .json is
	#taken out of the get-parameter that is called id, stripped down so
	#it will only contain the id of the post. And the user will be
	#redirected to the correct url. If the user entered the .json in
	#the right place, right after blogpost, the post will be fetched
	#from the database, and sent to permalink.html. If the id in the
	#url is not leading to a post, then the user will be redirected
	#to the blog.
	def get(self):
		key = self.request.get('id')
		if key.find('.json') != -1:
			self.json_redirect(key)
		else:
			post = db.get(key)
		
			if not post:
				self.redirect('/blog')
				return 
			
			self.render("permalink.html", post = post)
	
	#if this function is called, it splits the string by the entered
	#value in split_by. Then it strips the key-string down so it will
	#not contain what was in split_by. Then a precausion by making sure
	#the rest of the key is actually a string and decodes it to unicode.
	#At last the function redirects the user to the correct url.
	def json_redirect(self, key):
		key_split = key.split('.json')
		key_strip = key_split[0].strip() 
		key_precode = str(key_strip) 
		key = key_precode.decode('unicode-escape')
		self.redirect('/blogpost.json?id=%s' % (key))
		

#If .json is added to the URL after /blogpost, but before the post key,
#the request will be handled by this handler. It collects the post's
#primary key from the URL, and findt the post in the database of posts.
#If there is no post with that key, the user will be redirected to /blog.
#...
class PostJson(MainHandler):
	def get(self):
		key = self.request.get('id')
		post = db.get(key)
		
		if not post:
			self.redirect('/blog')
			return

		self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
		self.write(json.dumps(post.toJson()))

#If .json is added to the URL after /blog, the request will be handled
#by this handler. ...
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

#This handler is used is a user uses the /newpost URL.
class NewPost(MainHandler):
    #if a user is logged in, it is ok and newpost is rendered. 
	#if user is not logged in, the user is redirected to the login page
	#for login.
	def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")
	
	#This happens if the submit button is pressed. First, the variable
	#user is checked to have a value. If not, the user is redirected to 
	#/blog, and the excecution exits. If there is a user present, 
	#subject and content will get values from the fields in the form in
	#newpost.html. If both have a value, a blogpost will be entered into
	#the database that contains posts, and the user is redirected to the
	#blog. If either subject or content don't have any value, an error
	#message will be generated and newpost.html is rendered over again.
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

#This is the mother class og Register. It is initialized with creating
#several veriables. Username, email, password is created with empty
#string. USER_RE, PASS_RE and EMAIL_RE is ...
class Signup(MainHandler):
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	PASS_RE = re.compile(r"^.{3,20}$")
	EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
	username = ''
	email = ''
	password = ''

#Checks ...
	def valid_username(self, username):
		return username and self.USER_RE.match(username)

	def valid_password(self, password):
		return password and self.PASS_RE.match(password)

	def valid_email(self, email):
		return not email or self.EMAIL_RE.match(email)

#When the /signup URL is entered, this get function is called, and the
#signupform is rendered.
	def get(self):
		self.render("signup-form.html")

#When the submit button is pressed in the signup form, this function is
#called.
	def post(self):
		have_error = False
		
		#collects the data from the form, and enters it into variables
		self.username = self.request.get('username')	
		self.password = self.request.get('password')
		verify = self.request.get('verify')
		self.email = self.request.get('email')
		
		#enters username and email into a dictionary called params
		params = dict(username = self.username, email = self.email)
		
		#if the username entered is not a valit username, an error
		#message is generated, and put in the params dictionary. 
		#have_error is set to True.
		if not self.valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		
		#if the password entered is not a valid password, an error
		#message is generated, and put in the params dictionary. 
		#have_error is set to True. 
		#Or if password and the verified password are not like, 
		#another error message is generated and have_error is also 
		#set to True.
		if not self.valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password !=verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True
		
		#if the entered email is not a valid email, an error
		#message is generated, and put in the params dictionary.
		#Have_errors is set to True.
		if not self.valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		#if have_errors is set to True, the user vil not be registered
		#but the signup form will be rendered again together with the 
		#content in the params dictionary. If have_errors is still False, the
		#done function is called and executed.
		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()
			
		#this function is overwritten by the done function in the 
		#Register class for this current code. 
		def done(self):
			self.redirect('/blog')

#When /signup URL is entered the actions will be handled by this 
#handler. This handler is a subclass of the above Signup-class. See
#comments for that class for handling of get and post and other
#functions. This class contains the done-method. It makes sure the 
#user doesn't already exist by looking up the user based on username, 
#then either gives the user en error message if the user already exist
#or calling the User's register function and puts the signed up user 
#in the database. Then user is logged in and the user is redirected
#to the blog.
class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

#When /login URL is entered, the get function is called and the login 
#form is rendered, and the user is able to enter username and password. 
#When the user presses submit button, the post function in this class 
#is called. Username and password is collected from the two input-field
#and added to their respective variables. Then login in User is called,
#and the returned value is put in the u-variable. Then... if a user is 
#returned, and u is not None, the login function in MainHandler is 
#called and the user gets logged in, and redirected to the blog. If
#a user with the entered password is not found in the database, an
#error message is returned, and the user will not be directed anywhere,
#by rendering the login form over again.
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

#When /logout URL is entered, the logout-function in MainHandler is 
#called. When it finished, the user is redirected to the blog (/blog)
class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

#spesification of which handler that are handled by which handler
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog', Blog),
                               ('/blogpost', Post),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog.json', BlogJson),
                               ('/blog/.json', BlogJson),
                               ('/blogpost.json', PostJson),
                               ],
                              debug=True)
