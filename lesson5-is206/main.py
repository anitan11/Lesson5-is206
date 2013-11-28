# -*- coding: utf-8 -*-
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

#this segment of code defines a working directory for templates, so it i easy refer to the html-files
web_dir = os.path.join(os.path.dirname(__file__), 'web')
JINJA_ENVIRONMENT = jinja2.Environment(loader = jinja2.FileSystemLoader(web_dir), autoescape=True)

secret = 'secret'	#the secret word used in the hashing

#When this function is called, it fetches the template defined and
#renders it with the parameters contained in params.
def render_str(template, **params):
	t = JINJA_ENVIRONMENT.get_template(template)
	return t.render(params)
	
#This functions returns a string val made up by the value in parameter
#and a hashed version of the secret word and the val combined.
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#When this function is called it takes the secure_val (the value 
#made in the make_secure_val function), splits it by the |, takes
#the first part of the string, that contains the val from 
#make_secure_val and checks it with the function. If the function
#(make_secure_val) returns the same hash as secure_val, then the value 
#is returned.
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#this function is not connected to a class. It returns the key of the
#blog.
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#creates a 5 character long salt
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

#This function, when called, creates a hashed password. If the salt has
#no value (None = default value for salt), a salt will be created. 
#Then a hashed version of the password will be made, and this function 
#returns a tring containing the salt, and the hashed password.
def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

#This function, when called, splits the value returned from make_pw_hash.
#Then it puts the first part of the hash, the salt, into the variable 
#salt. Then this function returns a True or False based on h is the 
#same as the hashed version of the parameters name and password, and
#the salt extracted from the h.
def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

#This function, when called, returns the hey value from the call
#to Google App Engine's db's Key's from_path function.
def users_key(group = 'default'):
    return db.Key.from_path('users', group)
		
#This is the main handler, and the mother class of many of the classes
#in this code.
class MainHandler(webapp2.RequestHandler):
    #This function, when called, will call the response's out's write
	#function. The *'s says that 'a' is a dictionary that can contain 
	#one or more values that is sent to the write function. The same 
	#with **kw. 
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	
	#This function, when called, ads a user field to the params 
	#dictionary that is containing a user. Then the function returns 
	#the value from the call to itself. This means that it returns 
	#an own dictinary for the user field.
	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	#This function, when called, will call the write function with
	#the value returned from render_str as a parameter.
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	#This function, when called, will put the value returned from
	#make_secure_val into cookie_val. Then a header will be added to a
	#cookie with a field name specified in name, and the value in
	#cookie_val as the value of that field. The Path-parameter specifies
	#where in the cookie directory of the brownser the cookie is going
	#to be saved.
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))
	
	#This function, when called, will get the field specified in
	#name varible from a cookie. it returns this filedname, and 
	#the value returned from check_secure_val function
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	#This function is a set-function that calles the set_secure_cookie 
	#function. The parameters are the string user_id, and the string
	#version of the id of the user's datastore key.
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	#This function, when called, sets the user-id header to empty
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	#This function, when calles, calles webapp2's requesthandler's 
	#initialize function with the request and response parameters given
	# as *a and **kw. This will initialize MainHandler with the given
	#WSGI app. Then the uid is set by calling the read_secure_cookie
	#function (it reads the user-id from the cookie) and puts this value
	#into the uid variable. Then it sets the user variable and fetches
	#the user with this id from the user database.
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

#The handler of root. When / URL is entered, index.html is rendered.
class MainPage(MainHandler):
  def get(self):
      self.render('index.html')
		
#this class contains the user database, and is a subclass of Google's 
#db.Model.
class User(db.Model):
    #each user will have these fields, and they are given a type.
	#field = type (restrictions)
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	#fetches the user by the given id in uid, and the value returned 
	#from users_key()
	@classmethod # makes the class of the object this function is called upon, the first argument (cls)
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	#fetches the user by the given name. Then it filters it by the name
	#and stores that user into u. Then it simply returns the user-objekt
	#in u.
	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	#when this function is called, it makes a hash out of the password
	#by calling the make_pw_hask function. Then it returns the 
	#user-object with with (new) values.
	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	#this function, when called, fetches the cls-objekt (most likely
	# a user) from the database by name, and stores
	#the object in the variable u. If u contains a value, and the 
	#password is valid, then this function returns u. If not, it does 
	#not return anything.
	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

#this class contains the post database, and is a subclass of Google's 
#db.Model.
class PostDB(db.Model):
	#each post will have these fields, and they are given a type.
	#field = type (restrictions)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	#This function, when called, renders posts to the post.html page
	#with the parameters p and key.
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self, key = str(self.key()))

	#This function, when called returns the json of a post. First it
	#defines the types to go in the json. Then it makes an empty json
	#calles output. Then it rund a loop that goes through every key and 
	#checks certain citerias. 
	def toJson(self):
		POST_TYPES = (str, str, datetime.date, datetime.date)
		output = {}
		for key in self.properties():
			value = getattr(self, key) #value = value stored in key
			if isinstance(value, datetime.date): #is value datetime.date-type?
				dthandler = lambda obj: obj.isoformat() if isinstance(obj, datetime.datetime) else None #dthandler formates date and time from the post, if existing
				output[key] = json.dumps(value, default=dthandler) #gjør om value til string i format bestemt av dthandler
			elif isinstance(value, str): #is value str-type?
				output[key] = value #puts value in dictinary
			elif isinstance(value, unicode): #is value unicode-type?
				output[key] = value.decode('unicode-escape') #decodes value to unicode, and puts it in dict
			elif isinstance(value, db.Model): #is value a dbModel-type?
				output[key] = to_dict(value) #puts the value inside the dictinary for later reading
			else:
				raise ValueError('cannot encode ' + repr(value)) #if not, raise error
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
#primary key from the URL, and finds the post in the database of posts.
#If there is no post with that key, the user will be redirected to /blog.
#Or else the site prints out the json by calling the the toJson function.
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
#by this handler. First, posts and post-content will be fetched
#from the database. Then json will be printed out by calling 
#json.dumps as a parameter in the write function.
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
#string. USER_RE, PASS_RE and EMAIL_RE is contains definitions of the 
#requirements for username, password and email.
class Signup(MainHandler):
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	PASS_RE = re.compile(r"^.{3,20}$")
	EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
	
	username = ''
	email = ''
	password = ''

#Checks of the username, password and email matches up to the 
#requirements defined in the above variables.
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
