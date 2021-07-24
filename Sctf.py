#!/usr/bin/python3
# Sctf

import pygeoip, markdown, werkzeug, astral.sun, astral.geocoder, css_html_js_minify
import quart; quart.htmlsafe_dumps = None
import quart.flask_patch
from quart import *
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import TextField, SelectField, BooleanField, IntegerField, PasswordField
from wtforms.validators import Email, EqualTo, Optional, DataRequired
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import HTTPException, InternalServerError
from utils.nolog import *

class PrefixedQuart(Quart):
	def prefix_static(self):
		if (not self.has_static_folder): return
		application_root = '/' + (self.config.get('APPLICATION_ROOT') or '').strip('/')
		if (not application_root.strip('/')): return
		self.static_url_path = application_root + self.static_url_path
		static_host = self.url_map.rules[0].host
		self.url_map = quart.routing.Map(self.url_map.host_matching)
		self.add_url_rule(
			f"{self.static_url_path}/<path:filename>", 'static', self.send_static_file,
			host=static_host,
		)

	def route(self, path, *args, **kwargs):
		return super().route((self.config.get('APPLICATION_ROOT') or '')+path, *args, **kwargs)

app = PrefixedQuart(__name__)
app.config.from_object('config')
app.register_error_handler(Exception, lambda ex: ex if (isinstance(ex, HTTPException)) else Sexcepthook(ex.__class__, ex, ex.__traceback__) or InternalServerError())
app.prefix_static()
db = SQLAlchemy(app)
lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'
#app.jinja_env.trim_blocks = True
#app.jinja_env.lstrip_blocks = True

setlogfile('Sctf.log')

tmpdir = app.config.get('TASKDATA_TMPDIR', '/tmp/Sctf')

freeports_tcp = set(range(*app.config.get('TASK_PORT_RANGE', (51200, 51300))))
freeports_udp = set(range(*app.config.get('TASK_PORT_RANGE', (51200, 51300))))
secret_key = hashlib.md5(app.config['SECRET_KEY'].encode()).hexdigest().encode()
rand_salt = hashlib.md5(secret_key).hexdigest()

discord_webhook = app.config.get('DISCORD_WEBHOOK')
if (discord_webhook is not None): discord_texts = app.config['DISCORD_TEXTS']

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	nickname = db.Column(db.String(128), index=True, unique=True, nullable=False)
	email = db.Column(db.String(256), index=True)
	discord_id = db.Column(db.Integer)
	password = db.Column(db.String(64), nullable=False)
	admin = db.Column(db.Boolean, nullable=False, default=False)
	solved = db.Column(db.String(1024), nullable=False, default='')

	def __repr__(self):
		return f"<User #{self.id} ({self.nickname})>"

	@property
	def score(self):
		return sum(taskset.tasks[i].cost for i in self.solved.split(',') if i in taskset.tasks)

db.create_all()
db.session.commit()

class LoginForm(FlaskForm):
	login = TextField('Login', validators=[DataRequired("Login is required.")])
	password = PasswordField('Password', validators=[DataRequired("Password is required.")])
	remember_me = BooleanField('Remember')

class RegisterForm(FlaskForm):
	nickname = TextField('Nickname', validators=[DataRequired("Nickname is required.")])
	email = TextField('E-Mail', validators=[DataRequired("E-Mail is required."), Email("E-Mail must be valid.")])
	discord_id = IntegerField('Discord id')
	password = PasswordField('Password', validators=[DataRequired("Password is required.")])
	password_repeat = PasswordField('Repeat password', validators=[DataRequired("Password repeat is required."), EqualTo('password', "Passwords must match.")])
	remember_me = BooleanField('Remember')

class EditUserForm(FlaskForm):
	nickname = TextField('Nickname')
	email = TextField('E-Mail', validators=[DataRequired("E-Mail is required."), Email("E-Mail must be valid.")])
	discord_id = IntegerField('Discord id')

class ChangePasswordForm(FlaskForm):
	current_password = PasswordField('Current password', validators=[DataRequired("Password is required.")])
	new_password = PasswordField('New password', validators=[DataRequired("New password is required.")])
	new_password_repeat = PasswordField('Repeat password', validators=[DataRequired("Password repeat is required."), EqualTo('new_password', "Passwords must match.")])

class AdminBaseUserForm(FlaskForm):
	nickname = TextField('Nickname')
	email = TextField('E-Mail', validators=[Optional(), Email("E-Mail must be valid if specified.")])
	discord_id = IntegerField('Discord id', validators=[Optional()])
	admin = BooleanField('Admin')

class AdminCreateUserForm(AdminBaseUserForm):
	password = PasswordField('Password', validators=[Optional()])
	password_repeat = PasswordField('Repeat password', validators=[EqualTo('password', "Passwords must match.")])

class AdminEditUserForm(AdminBaseUserForm):
	user = SelectField('User', coerce=int)

class AdminDeleteUserForm(FlaskForm):
	user = SelectField('User', coerce=int)

class AdminPasswordResetForm(FlaskForm):
	user = SelectField('User', coerce=int)
	password = PasswordField('Password', validators=[DataRequired("Password is required.")])
	password_repeat = PasswordField('Repeat password', validators=[DataRequired("Password repeat is required."), EqualTo('password', "Passwords must match.")])

class AdminSubsUserForm(FlaskForm):
	user = SelectField('User', coerce=int)

async def validate_form(form):
	res = form.validate_on_submit()
	for field, errors in form.errors.items():
		for error in errors:
			#await flash(f"Error in field «{form[field].label.text}»: {error}")
			await flash(f"Error: {error}")
	return res

@app.before_request
def before_request():
	g.taskset = taskset
	g.user = current_user
	g.night = taskset.config.get('always_night') or is_night(request.headers.get('X-Forwarded-For', request.remote_addr))
	g.custom_css = os.path.exists(os.path.join(taskset.path, 'custom.css'))

	g.contest_started = (taskset.config.get('contest_started') or 'contest_start' not in taskset.config or time.localtime() >= time.strptime(taskset.config['contest_start'], '%d.%m.%y %H:%M'))
	g.contest_ended = (taskset.config.get('contest_ended') or 'contest_end' in taskset.config and time.localtime() >= time.strptime(taskset.config['contest_end'], '%d.%m.%y %H:%M'))
	g.contest_running = (g.contest_started and not g.contest_ended)

	g.builtins, g.operator = builtins, operator

@app.after_request
def after_request(r):
	#if ('text/html' in r.content_type): r.set_data(css_html_js_minify.html_minify(r.get_data(as_text=True)))
	return r

def password_hash(password): return generate_password_hash(password, method='sha256')

def mktoken(id: int, data: bytes) -> str:
	id = VarInt.pack(id)
	return id.hex()+hashlib.md5(data+hashlib.md5(secret_key).digest()+id).hexdigest()

def check_token(token: [str, bytes], data: bytes) -> [int, None]:
	if (not isinstance(token, str)):
		try: token = token.decode('ascii')
		except ValueError: return None
	token = token.strip()
	try: id = VarInt.read(io.BytesIO(bytes.fromhex(token)))
	except Exception as ex: return None #logexception(ex, repr(token))
	if (token != mktoken(id, data)): return None
	return id

@dispatch
@lm.user_loader
def load_user(id: int):
	return User.query.filter_by(id=id).first()

@dispatch
def load_user(**kwargs):
	return User.query.filter_by(**kwargs).first()

@lm.request_loader
def load_user_from_request(request):
	header = request.headers.get('Authorization')
	if (header is None): return None
	header = header.replace('Basic ', '', 1).strip()
	try: header = base64.b64decode(header)
	except TypeError: pass
	if (header != app.config['SECRET_KEY'].encode()): return None
	return load_user(id=0, nickname='admin')

def task_dir(id): return os.path.join('tasks', secure_filename(id))
def load_task(id): return json.load(open(os.path.join(task_dir(id), 'task.json')))

class Taskset:
	__slots__ = ('path', 'config', 'tasks')

	def __init__(self, path):
		self.path = path
		self.config = json.load(open(os.path.join(path, 'taskset.json')))
		self.tasks = {i: Task(self, i, **load_task(i)) for i in os.listdir(os.path.join(path, 'tasks'))}

	@itemget
	@lrucachedfunction
	def cat(self, cat):
		return [i for i in self.tasks.values() if i.cat == cat]

	@property
	@lrucachedfunction
	def cats(self):
		return {cat: self.cat[cat] for cat in sorted({i.cat for i in self.tasks.values()})}

	@property
	def flag_prefix(self):
		return self.config.get('flag_prefix', 'flag')

	@attrget
	def default(self, x):
		return Sdict(self.config.get('default', {}).get(x, {}))

class Task:
	__slots__ = ('taskset', 'id', 'title', 'cat', 'scoring', 'flag', 'desc', 'dir', 'cgis', 'daemons', 'files')

	@init_defaults
	def __init__(self, taskset, id, *, title, cat, cost, flag):
		self.taskset, self.id, self.title, self.cat = taskset, id, title, cat

		if (isnumber(cost)): self.scoring = Scoring(cost)
		else:
			if (cost == 'default'): cost = {}
			cost = self.taskset.default.cost & cost
			self.scoring = allsubclassdict(Scoring)[f"Scoring_{cost['dynamic']}"](self, **cost)

		try: flag = flag['static']
		except (TypeError, KeyError): pass

		if (isinstance(flag, str)):
			self.flag = Flag(flag)
			assert (re.match(r'%s{.*}' % self.taskset.flag_prefix, self.flag.flag))
		else:
			if (flag == 'default'): flag = {}
			flag = (self.taskset.default.flag & flag)
			self.flag = allsubclassdict(Flag)[f"Flag_{flag['dynamic']}"](self, **flag)

		self.dir = task_dir(id)

		self.desc = markdown.markdown(open(os.path.join(self.dir, 'task.md')).read())

		filesdir = os.path.join(self.dir, 'files')
		self.files = os.listdir(filesdir) if (os.path.isdir(filesdir)) else ()

		if (os.path.isdir(os.path.join(self.dir, 'cgi'))): self.cgis = CGIs(self)
		if (os.path.isdir(os.path.join(self.dir, 'daemons'))): self.daemons = Daemons(self)

	def __repr__(self):
		return f"<Task '{self.id}' ({self.title})>"

	def format_desc(self):
		host = app.config.get('TASK_HOSTNAME', app.config.get('HOSTNAME', socket.gethostname()))
		ip = socket.gethostbyname(host)
		if (app.config.get('USE_IP_AS_HOST', False)): host = ip

		d = Sdict({'': ''})

		if (getattr(self, 'cgis', None)): d['cgi'] = S({proto: S({
				'ip': ip,
				'host': host,
				'port': cgi.port,
				'token': mktoken(g.user.id, self.id.encode()),
			}) for proto, cgi in self.cgis.cgis.items()})

		if (getattr(self, 'daemons', None)): d['daemon'] = S({proto: S({
				'ip': ip,
				'host': host,
				'env': daemon.env,
				'port': daemon.port,
				**({'url': daemon.url} if (hasattr(daemon, 'url')) else {}),
				'token': mktoken(g.user.id, self.id.encode()),
			}) for proto, daemon in self.daemons.daemons.items()})

		class _Fmt(string.Formatter):
			def get_field(self, x, args, kwargs):
				try: return super().get_field(x, args, kwargs)
				except (KeyError, AttributeError): return (x.join('{}'), x)

		try: return _Fmt().format(self.desc, **d)
		except Exception as ex: logexception(ex, self); return self.desc

	async def file(self, file, uid=None):
		filename = os.path.join(self.dir, file)

		if (os.path.islink(filename) and os.path.splitext(os.path.basename(os.path.realpath(filename)))[0] == os.path.splitext(os.path.basename(filename))[0]):
			return await self.compile_src(os.path.realpath(filename), uid, outext=os.path.splitext(file)[1])

		return filename

	#@aiocache.cached()
	async def compile_src(self, srcfilename, uid=None, *, outext=None):
		if (uid is not None): flag = taskset.tasks[self.id].flag.get_flag(uid)
		else: flag = None

		ext = os.path.splitext(srcfilename)[1]
		os.makedirs(tmpdir, exist_ok=True)
		outfilename = tempfile.mkstemp(dir=tmpdir, prefix='taskdata_', suffix=outext if (outext is not None) else None)[1]

		if (ext == '.sh'): cmd = f"""FLAG={repr(flag)} {srcfilename} {outfilename}"""
		elif (ext == '.c'): cmd = f"""tcc {f'''-DFLAG='"{flag}"' ''' if (flag is not None) else ''}{srcfilename} -o {outfilename}"""
		elif (ext == '.py'): cmd = f"""env {f'''FLAG={repr(flag)} ''' if (flag is not None) else ''}python3 {srcfilename} {outfilename}"""
		elif (ext == '.go'): cmd = f"""go build {f'''-ldflags "-X main.FLAG={flag}" ''' if (flag is not None) else ''}-o {outfilename} {srcfilename}"""
		else: raise NotImplementedError(ext)
		p = await asyncio.create_subprocess_shell(cmd, cwd=os.path.dirname(srcfilename))
		assert (await p.wait() == 0)

		return outfilename

	@property
	def solved(self):
		return sum(self.id in u.solved.split(',') for u in User.query.filter_by(admin=False).all())

	@property
	def solved_by(self):
		return [u for u in User.query.filter_by(admin=False).all() if self.id in u.solved.split(',')]

	@property
	def cost(self):
		return self.scoring.cost

	@property
	def cost_stable(self):
		return self.scoring.cost_stable

class Flag:
	__slots__ = ('flag',)

	def __init__(self, flag):
		self.flag = flag

	def get_flag(self, uid):
		try: return self.flag
		except AttributeError: return None

	def validate_flag(self, uid, flag):
		return (flag == self.get_flag(uid))

### TODO:
#class Flag_caseless(Flag):
#	def get_flag(self, uid):
#		return super().get_flag().casefold()
#
#	def validate_flag(self, uid, flag):
#		return (flag.casefold() == self.get_field(uid))
###

class Flag_dynamic(Flag):
	__slots__ = ('task',)

	@abc.abstractproperty
	def get_flag(self, uid):
		pass

class Flag_regex(Flag_dynamic):
	__slots__ = ('pattern',)

	def __init__(self, task, *, dynamic, pattern):
		assert (dynamic == 'regex')
		self.task, self.pattern = task, pattern

	def validate_flag(self, uid, flag):
		return re.match(self.pattern, flag) is not None

class Flag_l33t(Flag_dynamic):
	__slots__ = ('pattern', 'caseless')

	leet = {
		'a': 'aA4@',
		'b': 'bB8',
		'c': 'cC',
		'd': 'dD',
		'e': 'eE3',
		'f': 'fF',
		'g': 'gG6',
		'h': 'hH',
		'i': 'iI!',
		'j': 'jJ',
		'k': 'kK',
		'l': 'lL1',
		'm': 'mM',
		'n': 'nN',
		'o': 'oO0',
		'p': 'pP',
		'q': 'qQ',
		'r': 'rR',
		's': 'sS5$',
		't': 'tT7',
		'u': 'uU',
		'v': 'vV',
		'w': 'wW',
		'x': 'xX',
		'y': 'yY',
		'z': 'zZ',
	}

	def __init__(self, task, *, dynamic, pattern, caseless=False):
		assert (dynamic == 'l33t')
		self.task, self.pattern, self.caseless = task, pattern, caseless

	def get_flag(self, uid):
		if (self.caseless): leet = {k: str().join(set(v.casefold())) for k, v in self.leet.items()}
		else: leet = self.leet
		rand = random.Random(rand_salt+str(uid))
		r = re.sub(r'{.*}', lambda x: x[0].translate({ord(i): rand.choice(leet.get(i, i)) for i in set(x[0])}), self.pattern)
		return r.casefold() if (self.caseless) else r

	def validate_flag(self, uid, flag):
		return super().validate_flag(uid, flag.casefold() if (self.caseless) else flag)

class Flag_random(Flag_dynamic):
	__slots__ = ('pattern', 'length', 'caseless')

	def __init__(self, task, *, dynamic, pattern=None, length=16, caseless=False):
		assert (dynamic == 'random')
		self.task, self.pattern, self.length, self.caseless = task, pattern if (pattern is not None) else task.taskset.flag_prefix+'{.}', length, caseless

	def get_flag(self, uid):
		# charset = string.ascii_lowercase if (self.caseless) else string.ascii_letters
		return self.pattern.replace('.', randstr(self.length, caseless=self.caseless, seed=rand_salt+str(uid)), 1)

	def validate_flag(self, uid, flag):
		return super().validate_flag(uid, flag.casefold() if (self.caseless) else flag)

class Flag_func(Flag_dynamic):
	__slots__ = ('code',)

	def __init__(self, task, *, dynamic, func):
		assert (dynamic == 'func')
		exec('def f(uid, flag):\n'+S('\n'.join(func) if (isiterablenostr(func)) else func).indent())
		self.task, self.func = task, f

	def validate_flag(self, uid, flag):
		return bool(self.func(uid, flag))

class Scoring:
	__slots__ = ('cost',)

	def __init__(self, cost):
		self.cost = cost

	def __str__(self):
		return str(self.cost)

	@property
	def cost_stable(self):
		return self.cost

class Scoring_dynamic(Scoring):
	__slots__ = ('task',)

	def __str__(self):
		cost, cost_stable = self.cost, self.cost_stable
		return str(cost) + str(cost_stable).join('()')*(cost != cost_stable)

	@abc.abstractproperty
	def cost(self):
		pass

	@abc.abstractproperty
	def cost_stable(self):
		pass

class Scoring_equal(Scoring_dynamic):
	__slots__ = ('initial',)

	def __init__(self, task, *, dynamic, initial=1000):
		assert (dynamic == 'equal')
		self.task, self.initial = task, initial

	@property
	def cost(self):
		return math.ceil(self.initial/max(1, self.task.solved))

	@property
	def cost_stable(self):
		return self.initial

class Scoring_decaying(Scoring_dynamic):  # from CTFd
	__slots__ = ('initial', 'decay', 'minimum')

	def __init__(self, task, *, dynamic, initial, decay, minimum):
		assert (dynamic == 'decaying')
		self.task, self.initial, self.decay, self.minimum = task, initial, decay, minimum

	@property
	def cost(self):
		decay = eval(self.decay.replace('N', str(User.query.filter_by(admin=False).count()), 1)) if (isinstance(self.decay, str)) else self.decay
		return math.ceil((self.minimum-self.initial) / decay**2 * max(0, self.task.solved-1)**2 + self.initial)

	@property
	def cost_stable(self):
		return self.initial

class CGIs:
	__slots__ = ('task', 'cgis')

	def __init__(self, task):
		self.task = task
		self.cgis = dict()

	def __getattr__(self, x):
		try: return self.cgis[x]
		except KeyError: raise AttributeError(x)

	async def start(self):
		for i in os.listdir(os.path.join(self.task.dir, 'cgi')):
			self.cgis[i] = subclassdict(CGI)[f"CGI_{i}"](self.task, await self.task.file(os.path.join('cgi', i)))
			await self.cgis[i].start()

class CGI:
	__slots__ = ('task', 'port')

class CGI_tcp(CGI):
	__slots__ = ('executable', 'server')

	def __init__(self, task, executable):
		self.task, self.executable = task, executable
		self.port = freeports_tcp.pop()

	def __del__(self):
		try: self.server.close()
		except AttributeError: pass
		try: freeports_tcp.add(self.port)
		except AttributeError: pass

	async def start(self):
		while (True):
			try: self.server = await asyncio.start_server(self.handle, '0.0.0.0', self.port)
			except OSError: self.port = freeports_tcp.pop()
			else: break

	@staticmethod
	async def _transfer(src, dest):
		while (True):
			data = await src.read(4096)
			if (not data): break
			dest.write(data)

	async def handle(self, reader, writer):
		#sock = writer.get_extra_info('socket')
		addr = writer.get_extra_info('peername')
		log(self.task, '+', addr)

		writer.write(b"Enter your token: ")
		await writer.drain()
		token = await reader.readline()
		proc = None

		uid = check_token(token, self.task.id.encode())
		if (uid is None):
			writer.write(b"Invalid token.\n")
			writer.write_eof()
		else:
			env = os.environ.copy()
			env['FLAG'] = self.task.flag.get_flag(uid)
			writer.write(b"\033[A\r\033[K")
			await writer.drain()
			#sock.setblocking(True)
			proc = await asyncio.create_subprocess_exec(os.path.abspath(self.executable), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, cwd=self.task.dir, env=env)
			loop = asyncio.get_event_loop()
			to_proc = loop.create_task(self._transfer(reader, proc.stdin))
			from_proc = loop.create_task(self._transfer(proc.stdout, writer))

		if (proc is not None):
			await asyncio.wait_for(proc.wait(), timeout=app.config.get('SUBPROCESS_TIMEOUT', 300))
			to_proc.cancel()
			from_proc.cancel()
		writer.close()
		log(self.task, '-', addr)

''' TODO:
class CGI_udp(CGI):
	class Protocol(asyncio.DatagramProtocol):
		def __init__(self, executable):
			self.executable = executable

		def connection_made(self, transport):
			self.transport = transport
			self.transport.sendto(b"Enter your token: ")

		@staticmethod
		async def _transfer_from(src, dest):
			while (True):
				data = await src.read(4096)
				if (not data): break
				dest.sendto(data)

		def datagram_received(self, data, addr):
			log(self.task, '+', addr)

			token = data
			proc = None

			uid = check_token(token, self.task.id.encode())
			if (uid is None): self.transport.sendto(b"Invalid token.\n")
			else:
				env = os.environ.copy()
				env['FLAG'] = self.task.flag.get_flag(uid)
				self.transport.sendto(b"\033[A\r\033[K")
				proc = await asyncio.create_subprocess_exec(os.path.abspath(self.executable), stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, cwd=self.task.dir, env=env)
				loop = asyncio.get_event_loop()
				#to_proc = loop.create_task(self._transfer(reader, proc.stdin))
				from_proc = loop.create_task(self._transfer_from(proc.stdout, self.transport))

			if (proc is not None):
				await asyncio.wait_for(proc.wait(), timeout=app.config.get('SUBPROCESS_TIMEOUT', 300))
				#to_proc.cancel()
				from_proc.cancel()
			log(self.task, '-', addr)

	__slots__ = ('executable', 'server')

	def __init__(self, task, executable):
		self.task, self.executable = task, executable
		self.port = freeports_udp.pop()

	def __del__(self):
		try: self.server.close()
		except AttributeError: pass
		try: freeports_udp.add(self.port)
		except AttributeError: pass

	async def start(self):
		while (True):
			try: self.endpoint = await asyncio.get_event_loop().create_datagram_endpoint(lambda: self.Protocol(self.executable), ('0.0.0.0', self.port))
			except OSError: self.port = freeports_udp.pop()
			else: break
'''

class Daemons:
	__slots__ = ('task', 'daemons')

	def __init__(self, task):
		self.task = task
		self.daemons = dict()

	def __getattr__(self, x):
		try: return self.daemons[x]
		except KeyError: raise AttributeError(x)

	async def start(self):
		for i in os.listdir(os.path.join(self.task.dir, 'daemons')):
			self.daemons[i] = subclassdict(Daemon)[f"Daemon_{i}"](self.task, await self.task.file(os.path.join('daemons', i)))

class Daemon:
	__slots__ = ('task', 'process', 'env', 'port')

	def __init__(self, task, executable):
		self.task = task
		self.env = self.get_env()
		self.process = subprocess.Popen(os.path.abspath(executable), stdin=subprocess.DEVNULL, stdout=sys.stderr, cwd=self.task.dir, env=self.env)

	def __del__(self):
		try: self.process.kill()
		except AttributeError: pass

	def get_env(self):
		env = os.environ.copy()

		try: env['FLAG'] = self.task.flag.flag
		except AttributeError: env['FLAG_SECRET'] = mktoken(int(self.task.id.encode().hex(), 16), str(id(app)).encode())

		return env

class Daemon_tcp(Daemon):
	def __del__(self):
		super().__del__()
		try: freeports_tcp.add(self.port)
		except AttributeError: pass

	def get_env(self):
		env = super().get_env()

		while (True):
			self.port = freeports_tcp.pop()
			try:
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
					s.bind(('', self.port))
			except OSError: continue
			else: break
		env['PORT'] = str(self.port)

		return env

class Daemon_udp(Daemon):
	def __del__(self):
		super().__del__()
		try: freeports_udp.add(self.port)
		except AttributeError: pass

	def get_env(self):
		env = super().get_env()

		while (True):
			self.port = freeports_udp.pop()
			try:
				with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
					s.bind(('', self.port))
			except OSError: continue
			else: break
		env['PORT'] = str(self.port)

		return env

class Daemon_http(Daemon):
	__slots__ = ('host', 'url')

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.host = app.config.get('HOSTNAME', socket.gethostname())
		self.url = f"https://{self.host}/web/{self.task.id}"

	def __del__(self):
		super().__del__()
		try: freeports_tcp.add(self.port)
		except AttributeError: pass

	def get_env(self):
		env = super().get_env()

		while (True):
			self.port = freeports_tcp.pop()
			try:
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
					s.bind(('', self.port))
			except OSError: continue
			else: break
		env['PORT'] = str(self.port)
		env['TOKEN_COOKIE'] = 'task_token_'+self.task.id

		return env

@lrucachedfunction
def _geoip(ip):
	rec = pygeoip.GeoIP('/usr/share/GeoIP/GeoIPCity.dat').record_by_addr(ip)
	return (rec['latitude'], rec['longitude'])

def is_night(ip=None):
	try: observer = astral.Observer(*_geoip(ip))
	except Exception: observer = astral.geocoder.lookup('Moscow', astral.geocoder.database()).observer
	try: start, end = astral.sun.night(observer)
	except Exception: return False
	return (start <= datetime.datetime.now(start.tzinfo) < end)

@app.route('/')
@login_required
async def index():
	return await render_template('index.html')

@app.route('/fonts.css')
async def fonts_css():
	return Response(await render_template('fonts.css'), mimetype='text/css')

@app.route('/custom.css')
async def custom_css():
	return await send_from_directory(taskset.path, 'custom.css')

@app.route('/custom/<path:filename>')
async def custom_static(filename):
	return await send_from_directory(os.path.join(taskset.path, 'static'), filename)

@app.route('/about')
async def about():
	return await render_template('about.html')

@app.route('/login', methods=('GET', 'POST'))
async def login():
	if (g.user and g.user.is_authenticated):
		next = request.args.get('url')
		return redirect(next or url_for('index'))

	form = LoginForm()
	if (await validate_form(form)):
		user = load_user(nickname=form.login.data)
		if (not user or not check_password_hash(user.password, form.password.data)):
			await flash("Incorrect login or password.")
			return redirect(url_for('login'))
		login_user(user, form.remember_me.data)
		return redirect(url_for('login'))

	return await render_template('login.html', form=form)

@app.route('/register', methods=('GET', 'POST'))
async def register():
	if (g.user and g.user.is_authenticated): return redirect(request.args.get('url') or url_for('index'))

	if (not taskset.config.get('registration_opened', True) or 'registration_open' in taskset.config and time.localtime() < time.strptime(taskset.config['registration_open'], '%d.%m.%y %H:%M')): return abort(403, "Registration is currently closed.")

	form = RegisterForm()
	if (await validate_form(form)):
		usern = load_user(nickname=form.nickname.data)
		usere = load_user(email=form.email.data)
		if (usern or usere):
			await flash(f"Пользователь с таким {'ником' if (usern) else 'e-mail'} уже существует.")
			return redirect(url_for('register'))
		else:
			user = User(nickname=form.nickname.data, email=form.email.data, password=password_hash(form.password.data), discord_id=form.discord_id.data)
			db.session.add(user)
			db.session.commit()
			log(f"User registered: {user}")
			login_user(user, form.remember_me.data)
			scoreboard_flag.set()
			return redirect(url_for('login'))

	return await render_template('register.html', form=form)

@app.route('/logout')
async def logout():
	logout_user()
	return redirect(url_for('index'))

@app.route('/change_password', methods=('GET', 'POST'))
@login_required
async def change_password():
	form = ChangePasswordForm()

	if (await validate_form(form)):
		if (not check_password_hash(g.user.password, form.current_password.data)):
			await flash("Current password is wrong.")
			return redirect(url_for('change_password'))

		g.user.password = password_hash(form.new_password.data)
		db.session.commit()

		await flash("Password changed successfully.")
		return redirect(url_for('index'))

	return await render_template('change_password.html', form=form)

@app.route('/tasks.json')
@login_required
async def tasks_json():
	if (not g.user.admin and not g.contest_started): return Response('{}', mimetype='application/json')

	return Response(json.dumps({i.id: {
		'title': i.title,
		'cat': i.cat,
		'cost': str(i.scoring),
		'desc': i.format_desc(),
		'solved': len(i.solved_by),
		'files': [(name, mktoken(g.user.id, hashlib.md5(os.path.abspath(os.path.join(i.dir, 'files', name)).encode()).digest())) for name in i.files],
	} for i in taskset.tasks.values()}, ensure_ascii=False, separators=',:'), mimetype='application/json')

@app.route('/submit_flag')
@login_required
async def submit_flag():
	id = request.args.get('id')
	flag = request.args.get('flag')

	task = taskset.tasks.get(id)
	if (task is None): return abort(404, f"No task with such id: <code>{task}</code>.")

	log(f"Got flag from {g.user} for {task}: '{flag}'")

	if (not g.user.admin and not g.contest_started): return "The contest has not started yet."
	if (not g.user.admin and g.contest_ended): return "The contest is over."

	if (not re.match(r'^%s{.*}$' % taskset.flag_prefix, flag)): return ("This is not a flag. Flag format is: «%s{...}»" % taskset.flag_prefix)
	if (not task.flag.validate_flag(g.user.id, flag.strip())): return ('Жуж' if (random.random() < .01) else 'Wrong')

	g.user.solved = ','.join(S(g.user.solved.split(',')+[id]).uniquize()).strip(',')
	db.session.commit()
	scoreboard_flag.set()

	if (not g.user.admin and discord_webhook is not None):
		try: r = requests.post(discord_webhook, json={
			'content': random.choice(discord_texts).format(f'<@{g.user.discord_id}>' if (g.user.discord_id) else g.user.nickname),
			'embeds': [{
				'title': task.title,
				'description': f"[{task.cost}]\n(solved by {len(task.solved_by)})",
				'url': f"http{'s'*(not app.config.get('NO_HTTPS', False))}://{socket.gethostbyname(host) if (app.config.get('USE_IP_AS_HOST', False)) else app.config.get('HOSTNAME', socket.gethostname())}"+url_for('index', _anchor=task.id),
				'color': 32767,
			}],
			**({
				'nickname': 'ЖУЖ',
				'avatar_url': "https://w0.pngwave.com/png/308/965/honey-bee-bizzy-b-s-tumblebus-tumble-bus-triple-crown-drive-bee-emoji-png-clip-art.png",
			} if (random.random() < .001) else {}),
		}).text
		except Exception as ex: logexception(ex)
		else:
			if (r): logexception(WTFException(r))

	return 'Success!'  # used in main.html template js

@app.route('/taskdata')
async def taskdata():
	id = request.args.get('id')
	file = request.args.get('file')
	token = request.args.get('token')
	filename = os.path.join(task_dir(id), 'files', file)

	if (not g.user.admin and not g.contest_started): return abort(403, "The contest has not started yet.")

	uid = check_token(token, hashlib.md5(os.path.abspath(filename).encode()).digest())
	if (uid is None): return abort(403)

	task = taskset.tasks[id]

	filename = await task.file(os.path.join('files', secure_filename(file)), uid)

	# Flask-like send_file():

	headers = dict()
	headers['Content-Disposition'] = f"attachment; filename={file}"
	headers['Content-Length'] = str(os.path.getsize(filename))

	#async with quart.static.async_open(filename, 'rb') as f:
	#	data = await f.read()
	async with aiofiles.open(filename, 'rb') as f:
		data = await f.read()

	return Response(data, mimetype=mimetypes.guess_type(os.path.basename(filename))[0] or quart.static.DEFAULT_MIMETYPE, headers=headers)

@app.route('/taskflag')
async def taskflag():
	secret = request.args.get('secret')
	token = request.args.get('token')

	if (secret is None or token is None): return abort(400)

	task = check_token(secret, str(id(app)).encode())
	if (task is None): return abort(403)

	task = taskset.tasks.get(bytes.fromhex(hex(int(task))[2:]).decode())
	if (task is None): return abort(404)

	uid = check_token(token, task.id.encode())
	if (uid is None): return abort(403)

	return Response(json.dumps({'task': task.id, 'uid': uid, 'flag': task.flag.get_flag(uid)}), mimetype='application/json')

@app.route('/web/<task>')
async def web(task):
	task = taskset.tasks.get(task)
	if (task is None): return abort(404, f"No task with such id: <code>{task}</code>.")
	if ('http' not in task.daemons.daemons): return abort(404, f"No web page for this task.")

	response = await make_response(redirect(f"http://{task.daemons.http.host}:{task.daemons.http.port}"))
	response.set_cookie('task_token_'+task.id, mktoken(g.user.id, task.id.encode()))
	return response

@app.route('/scoreboard')
async def scoreboard():
	if (not g.user.is_authenticated and not taskset.config.get('public_scoreboard', True)): return abort(403, "Scoreboard is not publicly visible.")
	if (not (g.user.is_authenticated and g.user.admin) and not g.contest_started): return abort(403, "The contest has not started yet.")

	scoreboard = sorted({i: i.score for i in User.query.all()}.items(), key=operator.itemgetter(1), reverse=True)
	return await render_template('scoreboard.html', scoreboard=scoreboard)

@app.route('/user/<nickname>')
@login_required
async def user(nickname):
	u = load_user(nickname=nickname)
	if (u is None): return abort(404)
	return await render_template('user.html', u=u)

@app.route('/flag')
async def flag():
	return abort(403, "Nope!")

@app.route('/lp/scoreboard')
async def lp_scoreboard():
	scoreboard_flag.clear()
	return str(int(await scoreboard_flag.wait()))

@app.route('/admin')
@login_required
async def admin():
	if (not g.user.admin): return abort(403)
	return await render_template('admin.html')

@app.route('/admin/create_user', methods=('GET', 'POST'))
@login_required
async def admin_create_user():
	if (not g.user.admin): return abort(403)

	form = AdminCreateUserForm()

	if (await validate_form(form)):
		user = User(nickname=form.nickname.data, email=form.email.data, password=password_hash(form.password.data), discord_id=form.discord_id.data, admin=form.admin.data)

		db.session.add(user)
		db.session.commit()
		scoreboard_flag.set()

		await flash(f"[Admin] {user} added.")
		return redirect(url_for('user', nickname=user.nickname))

	return await render_template('admin/create_user.html', form=form)

@app.route('/admin/edit_user', methods=('GET', 'POST'))
@login_required
async def admin_edit_user():
	if (not g.user.admin): return abort(403)

	form = AdminEditUserForm()
	form.user.choices = [(u.id, u.nickname) for u in User.query.all()]

	if (await validate_form(form)):
		user = load_user(id=form.user.data)

		user.nickname = form.nickname.data
		user.email = form.email.data
		user.discord_id = form.discord_id.data
		user.admin = form.admin.data

		db.session.add(user)
		db.session.commit()
		scoreboard_flag.set()

		await flash(f"[Admin] {user} saved.")
		return redirect(url_for('user', nickname=user.nickname))

	try: user = load_user(id=int(request.args.get('user'))) or raise_(KeyError)
	except Exception: pass
	else:
		form.user.data = user.id
		form.nickname.data = user.nickname
		form.email.data = user.email
		form.discord_id.data = user.discord_id
		form.admin.data = user.admin

	return await render_template('admin/edit_user.html', form=form)

@app.route('/admin/delete_user', methods=('GET', 'POST'))
@login_required
async def admin_delete_user():
	if (not g.user.admin): return abort(403)

	form = AdminDeleteUserForm()
	form.user.choices = [(u.id, u.nickname) for u in User.query.all()]

	if (await validate_form(form)):
		user = load_user(id=form.user.data)

		db.session.delete(user)
		db.session.commit()
		scoreboard_flag.set()

		await flash(f"[Admin] {user} deleted.")
		return redirect(url_for('index'))

	try: user = load_user(id=int(request.args.get('user'))) or raise_(KeyError)
	except Exception: pass
	else: form.user.data = user.id

	return await render_template('admin/delete_user.html', form=form)

@app.route('/admin/reset_password', methods=('GET', 'POST'))
@login_required
async def admin_reset_password():
	if (not g.user.admin): return abort(403)

	form = AdminPasswordResetForm()
	form.user.choices = [(u.id, u.nickname) for u in User.query.all()]

	if (await validate_form(form)):
		user = load_user(id=form.user.data)

		user.password = password_hash(form.password.data)

		db.session.add(user)
		db.session.commit()

		await flash("[Admin] Password saved.")
		return redirect(url_for('index'))

	try: user = load_user(id=int(request.args.get('user'))) or raise_(KeyError)
	except Exception: pass
	else: form.user.data = user.id

	return await render_template('admin/reset_password.html', form=form)

@app.route('/admin/subs_user', methods=('GET', 'POST'))
@login_required
async def admin_subs_user():
	if (not g.user.admin): return abort(403)

	form = AdminSubsUserForm()
	form.user.choices = [(u.id, u.nickname) for u in User.query.all()]

	if (await validate_form(form)):
		user = load_user(id=form.user.data)
		login_user(user)

		await flash(f"[Admin] Now logged in as {user}")
		return redirect(url_for('index'))

	try: user = load_user(id=int(request.args.get('user'))) or raise_(KeyError)
	except Exception: pass
	else: form.user.data = user.id

	return await render_template('admin/subs_user.html', form=form)

@app.route('/admin/get_flag')
@login_required
async def admin_get_flag():
	if (not g.user.admin): return abort(403)

	task = request.args.get('task')
	user = request.args.get('user')
	token = request.args.get('token')

	if (task is None or not (user is not None or token is not None)): return abort(400, "Usage: <code>/?task=&lt;task&gt;&user=&lt;uid&gt;</code> or <code>/?task=&lt;task&gt;&token=&lt;token&gt;</code>.")

	task = taskset.tasks.get(task)
	if (task is None): return abort(404, f"No task with such id: <code>{task}</code>.")

	if (token is not None):
		user = check_token(token, task.id.encode())
		if (user is None): return abort(403, "Invalid token.")

	return task.flag.get_flag(user)

@app.route('/admin/restart')
@login_required
async def admin_restart():
	if (not g.user.admin): return abort(403)

	loop = asyncio.get_event_loop()
	loop.call_later(1, lambda: exit())

	return redirect(request.referrer or url_for('index'))

@app.route('/admin/reload_tasks')
@login_required
async def admin_reload_tasks():
	if (not g.user.admin): return abort(403)

	try: load_tasks()
	except Exception as ex: await flash(f"Error reloading tasks: {ex}.")
	else: log("Tasks reloaded."); await flash("Tasks reloaded successfully.")

	return redirect(request.referrer or url_for('index'))

def load_tasks():
	global taskset

	assert (not glob.has_magic(tmpdir))
	stale_taskdata = os.path.join(tmpdir, 'taskdata_*')
	log(f"Removing stale taskdata: {stale_taskdata}")
	for i in glob.iglob(stale_taskdata):
		os.remove(i)

	taskset = Taskset('.')

	loop = asyncio.get_event_loop()
	for i in taskset.tasks.values():
		if (hasattr(i, 'cgis')):
			loop.create_task(i.cgis.start())
		if (hasattr(i, 'daemons')):
			loop.create_task(i.daemons.start())

	scoreboard_flag.set()

@app.before_first_request
def init():
	global scoreboard_flag
	scoreboard_flag = asyncio.Event()
	load_tasks()

@apmain
@aparg('-p', '--port', type=int)
@aparg('--debug', action='store_true')
def main(cargs):
	port = cargs.port or random.Random(sys.argv[0]+'|'+os.getcwd()).randint(60000, 65535)
	if (cargs.debug): app.env = 'development'; setlogfile(None); app.run(port=port, debug=True, use_reloader=False)  # no autoreload to support cgis
	else: app.run('0.0.0.0', port=port)

if (__name__ == '__main__'): exit(main())

# by Sdore, 2021
