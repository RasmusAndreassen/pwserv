from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path

# Use bcrypt for password handling
import bcrypt

COMMONFILE = 'xato-net-10-million-passwords-10000.txt'
PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = b':'

app = Flask(__name__)
# The secret key here is required to maintain sessions in flask
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Initialize Database file if not exists.
if not os.path.exists(PASSWORDFILE):
	open(PASSWORDFILE, 'w').close()

def loadusers()->dict[bytes,bytes]:
	with open(PASSWORDFILE, 'rb') as f:
		return dict(entry.strip().split(PASSWORDFILEDELIMITER) for entry in f.readlines())

def storeusers(users:dict[bytes,bytes])->None:
	with open(PASSWORDFILE, 'wb') as f:
		f.write(b'\n'.join(username + PASSWORDFILEDELIMITER + password for username, password in users.items()))

def substitute(password:str) -> list[str]:
	substitutes = [password]

	for i, char in enumerate(password):
		match char:
			case '0':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'o' + subst[i+1:])
			case '@':
				old = substitutes.copy()
				for subst in old:
					substitutes.append(subst[:i] + 'a' + subst[i+1:])
				for subst in old:
					substitutes.append(subst[:i] + 'o' + subst[i+1:])
			case '5':
				for subst in substitutes.copy():
					substitutes.append(password[:i] + 's' + password[i+1:])
			case '2':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 's' + subst[i+1:])
			case '4':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'a' + subst[i+1:])
			case '1':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'i' + subst[i+1:])
			case '!':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'i' + subst[i+1:])
			case '3':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'e' + subst[i+1:])
			case '_':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + subst[i+1:])
			case ' ':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + subst[i+1:])
			case '.':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + subst[i+1:])
			case '(':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'c' + subst[i+1:])
			case '[':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'c' + subst[i+1:])
			case '{':
				for subst in substitutes.copy():
					substitutes.append(subst[:i] + 'c' + subst[i+1:])

	return substitutes

def valid_password(password:bytes) -> int:
	has_english_alpha=False
	has_other=False
	upper=False
	lower=False
	num=False
	special=False

	fail=False

	password:str = password.decode('utf-8')

	if len(password) < 8:
		flash('Password too short, at least 8 characters required')
		fail = True

	for char in password:
		if char.islower():
			lower = True
		if char.isupper():
			upper = True
		if char.isalpha():
			has_english_alpha=True
		if char.isdigit():
			num = True
		if not char.isalnum():
			special = True
		if not char.isascii():
			has_other=True

	if (has_english_alpha and not has_other) and not (upper and lower):
		flash('Must have both upper and lower case letters')
		fail = True
	if not num or not special:
		flash('Please include both numbers and special characters in your password')
		fail = True

	with open(COMMONFILE, 'r') as f:
		common = f.read().splitlines(keepends=False)

	if password in common:
		flash('Password too common')
		fail = True

	substitutes = substitute(password.lower())

	for subst in substitutes:
		if subst in common:
			flash('Password too common')
			fail=True
			break

	return not fail

def adduser(credentials:dict[str,str]) -> bool:
	username, password = credentials['username'].encode('utf-8'), credentials['password'].encode('utf-8')
	matchpwd = credentials['matchpassword'].encode('utf-8')

	if len(password) == 0 or len(username) == 0:
		flash('Please provide both username and password')

	if matchpwd != password:
		flash('Passwords do not match')
		return False

	if not valid_password(password):
		return False

	users = loadusers()
	if username in users.keys():
		flash('Username already exists')
		return False

	salt = bcrypt.gensalt()
	hashed = bcrypt.hashpw(password, salt)

	users[username] = hashed

	storeusers(users)
	
	return True

def authorise(credentials:dict[str,str]) -> bool:
	username, password = credentials['username'].encode('utf-8'), credentials['password'].encode('utf-8')
	
	users = loadusers()
	if not username in users.keys():
		flash('No such user')
		return False

	if not bcrypt.checkpw(password, users[username]):
		flash('Invalid password')
		return False

	return True

@app.route('/')
def home():
	username = None
	if 'logged_in' in session and session['logged_in'].encode('utf-8') in loadusers().keys():
		username = session['logged_in']
	
	return render_template('home.html', username=username)


# Display register form
@app.route('/register', methods=['GET', 'POST'])
def register():
	match request.method:
		case 'POST':
			if adduser(request.form):
				return redirect('/')
		case 'GET':
			pass

	return render_template('register.html')

# Display login form
@app.route('/login', methods=['GET', 'POST'])
def login():
	match request.method:
		case 'POST':
			if authorise(request.form):
				session['logged_in'] = request.form['username']
				return redirect('/')
		case 'GET':
			pass

	return render_template('login.html')

if __name__ == '__main__':
	app.run(debug=True)

a = '''uwsgi -s /tmp/pwserv.sock --manage-script-name --mount /=app:app'''
