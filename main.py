#!/usr/bin/env python
#
# CCC project for superintendents
#
import webapp2
import os
import jinja2
import cgi
import re
import random
import string
import hashlib
import json
import logging
import time
import datetime
from datetime import timedelta

from google.appengine.api import memcache
from google.appengine.ext import ndb
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#Handler everything html inherits from
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def get_login(self):
        user_cookie_val = self.request.cookies.get('username')
        if not user_cookie_val:
            return None
        else:
            return user_cookie_val
    def get_organization(self):
        organization_cookie_val = self.request.cookies.get('organization')
        if not organization_cookie_val:
            return None
        else:
            return organization_cookie_val
            
    def notfound(self):
        self.error(404)
        self.write('<h1>404: Not Found</h1> Sorry! The page you are looking for does not exist.')
        
#for getting date info from the path
def getinfo(organization, path):
	year = int(path[0:4])
	month = int(path[5:7])
	day = int(path[8:10])
	logging.error("year: " + str(year) + " month: " + str(month) + " day: " + str(day))
	today = datetime.date(year,month,day)
	today -= datetime.timedelta(days=1)
	yesterday = today
	today += datetime.timedelta(days=2)
	tomorrow = today
	today -= datetime.timedelta(days=1)
	logging.error("today: %s" % (today))
	logging.error("tomorrow: %s" % (tomorrow))
	logging.error("yesterday: %s" % (yesterday))
	date = today.strftime("%y-%m-%d")
	logging.error("paty: %s" % (path))
	yesterday_ref = organization + "/" + yesterday.strftime("%Y-%m-%d")
	tomorrow_ref = organization + "/" + tomorrow.strftime("%Y-%m-%d")
	weekday = today.strftime("%A")
	logging.error("weekday: %s" % weekday)
	month = today.strftime("%b")
	logging.error("month: %s" % month)
	day = today.strftime("%d")
	logging.error("day: %s" % day)
	return yesterday_ref, tomorrow_ref, weekday, month, day

def getdate():
	day = datetime.date.today()
	today = day.strftime("%Y-%m-%d")
	return today
	
# for figuring out the path and date
def findlast(s):
	#old_string = "this is going to have a full stop. some written sstuff!"
	k = s.rfind("/")
	path = s[:k] 
	date = s[k+1:]
	org = s[1:k]
	return org, date, path
		
#for hashing usernames and passwords
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salty = h.split('|')[1]
    return make_pw_hash(name, pw, salty)==h

#username and password +hash storage
class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    mail = ndb.StringProperty()
    organization = ndb.StringProperty(required = True)
    unpwhash = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

#signup membership form            
class SignUpHandler(Handler):
    def write_form(self, username="", error_un="", password="", error_pw="", verify="", error_v="", email="", error_e="", organization="", error_o=""):
        self.render("signup.html", username=cgi.escape(username, quote=True), error_un=error_un,
            password=cgi.escape(password, quote=True),
            error_pw=error_pw,
            verify=cgi.escape(verify, quote=True),
            error_v=error_v,
            email=cgi.escape(email, quote=True),
            error_e=error_e,
	    organization=cgi.escape(organization, quote="True"),
	    error_o=error_o)    
        
    def get(self):
        self.write_form()
        
    def post(self):    
        error_un = ""
        error_pw = ""
        error_v = ""
        error_e = ""
	error_o = ""
        valid_u = valid_username(self.request.get('username'))
        user_duplicat = dupuser(self.request.get('username'))
        valid_p = valid_password(self.request.get('password'))
        valid_v = valid_verify(self.request.get('password'), self.request.get('verify'))
        valid_e = valid_email(self.request.get('email'))
	valid_o = valid_organization(self.request.get('organization'))	
	
        if not (valid_u):
            error_un = "Invalid Username"
        
        if not (valid_p):
            error_pw = "Invalid Password"
        
        if not (valid_v):
            error_v = "Password and Verification do not match"   
        
        if not (valid_e):
            error_e = "Invalid Email"

	if not (valid_o):
	    error_e = "Invalid Organization Name"
        
        if not (user_duplicat):
            error_un = "That username already exists. Please pick another user name."
            
        if not (valid_u and valid_p and valid_v and valid_e and user_duplicat):
            self.write_form(self.request.get('username'), error_un,
            self.request.get('password'), error_pw,
            self.request.get('verify'), error_v,
            self.request.get('email'), error_e,
	    self.request.get('organization'), error_o)
        
        else: 
	    today = getdate()
            u_name = self.request.get('username')
            u_pw = self.request.get('password')
            u_email = self.request.get('email')
            u_organization = self.request.get('organization')
            u_organization = u_organization.replace(' ', '_')
            u_hash = make_pw_hash(u_name, u_pw)
            u = User(username=u_name, mail=u_email, unpwhash=u_hash, organization=u_organization)
            u_key = u.put()
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' %str(u_name))
            self.response.headers.add_header('Set-Cookie', 'valid=%s; Path=/' %str(u_hash))
            self.response.headers.add_header('Set-Cookie', 'organization=%s; Path=/' %str(u_organization))
	    logging.error('the value or organization: ' + str(u_organization))
            self.redirect('/%s/%s' %(str(u_organization), str(today)))
        
#functions for validating signup input
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_organization(organization):
    return USER_RE.match(organization)

def valid_username(username):
    return USER_RE.match(username)
    
PW_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PW_RE.match(password)
    
def valid_verify(password, verify):
    return password==verify
    
E_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    blank = email == ""
    match = E_RE.match(email)
    return blank or match

def dupuser(username):
    q = User.query(User.username == username)
    result = q.get()
    return result==None

        
#LoginHandler class
class LoginHandler(Handler):
    def write_form(self, username="", password="", error=""):
        self.render("login.html", username=cgi.escape(username, quote=True), 
        password=cgi.escape(password, quote=True), error = error)
   
    def get(self):
        self.write_form()   
        
    def post(self):    
        error = ""
        username = self.request.get('username')
        password = self.request.get('password')
        check_user = User.query(User.username == username)
        result = check_user.get()
                
        if result==None:
            error = "Username does not exist"
            self.write_form(username, password, error)
        
        else:
            saltyhash = result.unpwhash
            valid_up = valid_pw(username, password, saltyhash)
            
            if not (valid_up):
                error = "Your password is incorrect"
                self.write_form(username, password, error)

            else:
				today = getdate()
				organization = result.organization
				self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' %str(username))
				self.response.headers.add_header('Set-Cookie', 'valid=%s; Path=/' %str(saltyhash))
				self.redirect('/%s/%s' %(str(organization), str(today)))

#LogoutHandler class
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','username=; Path=/')
        self.response.headers.add_header('Set-Cookie','valid=; Path=/')
        self.redirect('/login')

#Content storage db
class Content(ndb.Model):
    path = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    
    @staticmethod
    def parent_key(path):
	rootstr = '/root%s' %path
	return ndb.Key(rootstr, 'pages')
    
    @classmethod
    def by_path(cls, path):
        q= Content.query(ancestor=cls.parent_key(path))
        q.order(-Content.created)
        return q
    
    @classmethod
    def by_id(cls, page_id, path):
        return cls.get_by_id(page_id, cls.parent_key(path))

#HomeHandler class
class HomeHandler(Handler):
    def get(self):
        username = self.get_login()
        loggedin = username
        organization = self.get_organization()
        if username:
			today = getdate()
			logging.error('not log in %s' % loggedin)
			self.redirect('/%s/%s' %(str(organization), str(today)))
        else:
			self.render('home.html')
			
class AboutHandler(Handler):
	def get(self):
		self.render('about.html')


#EditPageHandler class
class EditPageHandler(Handler):
    def render_editform(self, path, c): #can add stuff for errors here later
        username = self.get_login()
        loggedin = username
        historypath = "/_history" + path
        #can add variables for errors later
        self.render("edit.html", username=username, c=c, path=path, loggedin=loggedin, historypath=historypath)
    
    def get(self, path):
        if not self.get_login():
            self.redirect("/login")
        
        v = self.request.get('v')
        c = None
        if v:
            if v.isdigit():
                c = Content.by_id(int(v), path)
            
            if not c:
                return self.notfound()
        else:
            c=Content.by_path(path).get() #get returns one, fetch would return the list
    
        self.render_editform(path, c)
            
    def post(self, path):
        if not self.get_login():
            self.redirect("/login")
        
        old_page = Content.by_path(path).get()
        content = self.request.get("content")
        
        if not (old_page or content):
            return
        elif not old_page or old_page.content != content:
            c = Content(parent = Content.parent_key(path), content=content, path=path)
            c.put()
            logging.error("Putting content in database: "+ path)
            logging.error("The content was: "+ content)
        
        self.redirect("%s" % path)

#WikiPageHandler class
class WikiPageHandler(Handler):
    def display_page(self, path, c):
        username = self.get_login()
        loggedin = username
        editpath = "/_edit" + path
        historypath = "/_history" + path
        organization, end, rest = findlast(path)
        logging.error(end)
        
			
        yesterday_ref, tomorrow_ref, weekday, month, day = getinfo(rest, end)
        
        logging.error(" %s" % c.content)
        organization = organization.replace('_', ' ')        
        self.render('anypage.html', organization=organization, c=c, loggedin=loggedin, username=username, 
					editpath=editpath, historypath=historypath, yesterday = yesterday_ref, 
					tomorrow = tomorrow_ref, weekday = weekday, month = month, day = day)
    
    def edit_page(self, path):
        editpath = "/_edit" + path
        self.redirect("%s" % editpath)
    
    def get(self, path):
        if not self.get_login():
            self.redirect("/login")
        
        v = self.request.get('v')
        
        c = None
        if v:
            if v.isdigit():
                logging.error("V is a digit. The value of v is: "+ str(v))
                c = Content.by_id(int(v), path)
            else:
                logging.error("V is NOT a digit. The value of v is: "+ str(v))
                
            if not c:
                return self.notfound()
        else:
            logging.error("There is no v: "+ str(v))
            c=Content.by_path(path).get() #get returns one, fetch would return the list
		
        if c:
            logging.error("The value of c is: "+ str(c))
            self.display_page(path, c)
        else:
			c = Content(path = path, content = 'No Tasks Today!')
			self.display_page(path,c) 
            #self.edit_page(path)
	
#HistoryHandler class
class HistoryPageHandler(Handler):
    def display_page(self, path, contents):
        username = self.get_login()
        loggedin = username
        self.render("history.html", contents=contents, loggedin=loggedin, username=username, path=path)
    
    def edit_page(self, path):
        editpath = "/_edit" + path
        self.redirect("%s" % editpath)
    
    def get(self, path):
        #check if content exists, if not go to edit
        #need to change this to use ancestor - look at example
        c = Content.by_path(path)
        c.fetch(limit = 100)
        contents = list(c)
        logging.error("Looking for this in content database, history: "+ path)
        if contents:
            self.display_page(path, contents)
        else: 
            self.edit_page(path)

#handler for dates and groups
class DateHandler(Handler):
	def display_page(self, path, c):
		username = self.get_login()
		loggedin = username
		editpath = "/_edit" + path
		historypath = "/_history" + path
		
		self.render("anypage.html", c=c, loggedin=loggedin, username=username, 
					editpath=editpath, historypath=historypath)
					
	def edit_page(self, path):
		editpath = "/_edit" + path
		self.redirect("%s" % editpath)
	
	def get(self, group, year, month, day):
			path = group + '/' + year + '/' + month + '/' +day
			if not self.get_login():
				self.redirect("/login")
			v = self.request.get('v')
			user =  self.get_login()
			c = None
			if v:
				if v.isdigit():
					logging.error("V is a digit. The value of v is: "+ str(v))
					c = Content.by_id(int(v), path)
				else:
					logging.error("V is NOT a digit. The value of v is: "+ str(v))
				if not c:
					return self.notfound()
			else:
				logging.error("There is no v: "+ str(v))
				c=Content.by_path(path).get() #get returns one, fetch would return the list
			if c:
				logging.error("The value of c is: "+ str(c))
				self.display_page(path, c)
			else:
				self.edit_page(path)
		

#Path Handlers
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/', HomeHandler), ('/about', AboutHandler), ('/signup', SignUpHandler), ('/login', LoginHandler), 
('/logout', LogoutHandler), ('/_edit' + PAGE_RE, EditPageHandler), ('/_history' + PAGE_RE, HistoryPageHandler), 
#webapp2.Route('/<group>/<year:\d{4}>/<month:\d{2}>/<day:\d{2}>', handler=DateHandler),
(PAGE_RE, WikiPageHandler)
], debug=True)
