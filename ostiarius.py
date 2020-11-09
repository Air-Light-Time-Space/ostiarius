import argparse
import base64
import datetime
import hashlib
import os
import random
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading

try:
    import secrets
except ImportError:
    import string
    class secrets:
        def token_urlsafe(size):
            return (''.join(random.SystemRandom().choice(string.printable.strip().translate({ord(c): None for c in '$:#?@&/\|`<>~.!;{}[]()\'"'})) for i in range(size)))

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


OPENSSL_PATH = '/usr/bin/openssl'
SSL_PROTOCOL = ssl.PROTOCOL_TLSv1_2
SSL_CIPHERS = 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH' # https://cipherli.st/
STATE = 'ethereal'

USER_CODE_LENGTH = 6        # Code length 5:                          Code length 6:                          Code length 7:
                            #   users   probabilty (single guess)   /   users   probabilty (single guess)   /   users   probabilty (single guess)
                            #     1             1:100,000           \     1             1:1,000,000         \     1             1:10,000,000
                            #    15             1:6,667             /    15             1:66,667            /    15             1:666,667
                            #    25             1:4000              \    25             1:40,000            \    25             1:400,000
                            #   100             1:1000  !           /   100             1:10,000            /   100             1:100,000
                            #   250             1:400   !!          \   250             1:4,000             \   250             1:40,000

def callback_function(conn, cert, errno, depth, result):
    print(cert)
    return True


# Okay, let's get started...
def main(args):

    outer_realm = 'default'
    database_name = 'ostiary.db'
    if args.realm:
        outer_realm = args.realm
        database_name = 'ostiary-{:s}.db'.format(outer_realm.lower())

    database_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), database_name)
    database_exists = os.path.exists(database_file)
    database_connection = sqlite3.connect(database_file, check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES)
    database_connection.row_factory = sqlite3.Row       # This lets us refer to database results by column name

    def die(error):
        cleanup(database_connection)
        print("ERROR: {0}".format(error))
        sys.exit(1)

    if not database_exists:
        if not args.quiet: print("Creating database at {0}".format(database_file))
        setup(database_connection, outer_realm)

    if args.no_ssl:
        if not args.quiet: print("WARNING! Operating with SSL disabled.\nAccess codes and admin credentials will be sent in the clear.\nUSE FOR TESTING PURPOSES ONLY")
        port = 8080
        use_ssl = False
    else:
        port = 4433
        use_ssl = True

    if args.port: port = args.port

    if use_ssl:
        ssl_context = ssl.SSLContext(protocol=SSL_PROTOCOL)
        ssl_context.check_hostname=False
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
        ssl_context.set_ciphers(SSL_CIPHERS)
  #      ssl_context.load_verify_locations("keypad_fw/public.cert")
        if args.cert_file:
            try:
                ssl_context.load_cert_chain(args.cert_file, keyfile=args.key_file)
            except ssl.SSLError as e:
                additional_info = "\nIf the key is not included in the certificate file be sure to specify --key-file" if not args.key_file else ""
                die("{0}: Could not validate ssl certificate{1}".format(args.cert_file, additional_info))
            except Exception as e:
                die("{0}: {1}".format(args.cert_file, str(e)))
            if not args.quiet: print("Adding {:s} to local certificate store.".format(args.cert_file))
            if get_certificate(database_connection, args.host) is not None:
                delete_certificate(database_connection, args.host)
            with open(args.cert_file, 'r') as cert_data:
                save_certificate(database_connection, args.host, cert_data.read())
        else:
            compound_cert = get_certificate(database_connection, args.host, cert_only=False)
            if get_cert_expiration(compound_cert) < datetime.datetime.utcnow():
                if not args.quiet: print("Certificate is expired!")
                delete_certificate(database_connection, args.host)
            if compound_cert is None or get_cert_expiration(compound_cert) < datetime.datetime.utcnow():
                if not args.quiet: print("Generating self-signed certificate...")
                certificate, key = generate_ssl_cert(state_name=STATE, locality_name=outer_realm, common_name=args.host, hush = not args.verbose)
                compound_cert = certificate + key                               # TODO: Implement hardware-based key storage
                save_certificate(database_connection, args.host, compound_cert)
            temporary_certificate_path = temporary_path(compound_cert)  # We have to do this because SSLContext wont accept file like objects, just an actual path
            ssl_context.load_cert_chain(temporary_certificate_path)
            os.remove(temporary_certificate_path)

            print(get_cert_expiration(compound_cert))

        if args.verbose: print(get_certificate(database_connection, args.host))

    class HTTPServerThreads(ThreadingMixIn, HTTPServer):
        database = database_connection      # This allows us to access the database from within RequestHandler using self.server.database
        database_lock = threading.RLock()   # And since we're only using the one database connection with a multithreaded server we will have to lock it on writes
        default_realm = outer_realm.lower()

    http_server = HTTPServerThreads((args.host, port), RequestHandler)
    if use_ssl: http_server.socket = ssl_context.wrap_socket(http_server.socket, server_side=True)
    if not args.verbose: http_server.RequestHandlerClass.log_message = lambda *args: None
    if not args.quiet: print("Starting server on {0}:{1}".format(args.host, port))
    if not args.quiet: print("(<Ctrl>-C to exit)")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        print('', end='\r')
        if not args.quiet: print("Goodbye")
        cleanup(database_connection)


# Authorizes (or not) a user to access resources of a realm
# Logs said access if succesful
# usage:
#   GET /<realm>/auth/<n digit user code>
#   where n is USER_CODE_LENGTH
def auth (db, lock, method, realm, args, **kw):
    if method is not 'GET': return(400, "Invalid request")
    if len(args) is not 1: return(400, "Invalid arguments")
    user_code = args[0]
    if user_code.isnumeric() and len(user_code) is USER_CODE_LENGTH:
        name = check_user_auth(db, user_code, realm)
        if name:
            log_access(db, lock, realm, name)
            return(200, "Auth")                                     # TODO: Implement rentdue response
        else:
            return(401, "No auth")
    else:
        return(400, "Invalid user code")


# Lets admins list and get information about system users
# Also lets admins set or remove fields in the user database and add or delete users
# usage:
#   GET /<default realm>/users                                  -   List all users of the system and their extended information
#   GET /<default realm>/users/<username>/<field name>          -   Show the value of a specific user field (comment, created, expires, uses, rentdue, frozen)
#   GET /<realm>/users/                                         -   List authorized users of the realm and their last auth time
#   GET /<realm>/users/<username>                               -   List information for a specific user
#   PUT /<realm>/users/<new username>                           -   Create a new user and add them to the given realm, returns the new user's access code
#   PUT /<default realm>/users/<username>/<field name>/<value>  -   Set the value of an editable field (comment, exipires, uses, rentdue, frozen) on a given user
#   DELETE /<realm>/users/<username>                            -   Delete user from realm
def users (db, lock, method, realm, args, **kw):

    if len(args) > 0: user_name = args[0].replace('%20', ' ')
    if method is 'GET':
        if len(args) is 0: return(200, "\n".join(normalize_nested_list(admin_list_users(db, realm))))       # List users
        user_info = get_user_info(db, realm, user_name)
        if not user_info: return(404, "User not found")
        if len(args) is 1: return(200, ", ".join([str(col) for col in user_info]))                           # List info of specific user
        try:
            info = user_info[args[1]]
        except IndexError:
            return(400, "Invalid arguments")
        if len(args) is 2: return(200, str(info))                                                           # Show value of specific field for specific user
        return(400, "Invalid request")
    if method is 'PUT':
        if len(args) < 1: return(400, "Invalid arguments")
        user_info = get_user_info(db, None, user_name)
        if len(args) is 1:                                                                                  # Add user
            if user_info:
                if realm:
                    if get_user_info(db, realm, user_name): return(409, "User already exists")
                    if add_user_to_realm(db, lock, user_name, realm): return(200, "OK")
                return(409, "User already exists")
            return(200, str(create_user(db, lock, user_name, realm=realm)).zfill(USER_CODE_LENGTH))
        if len(args) is 3:                                                                                  # Set value of field on user
            if realm: return(400, "Invalid arguments")
            if not user_info: return(404, "User not found")
            try:
                user_info[args[1]]
            except IndexError:
                return(400, "Invalid arguments")
            if args[1] in ['code', 'created']: return(451, "Cannot edit static field")
            if not update_user(db, lock, user_name, args[1], args[2]): return(406, "Not acceptable")
            return(200, "OK")
        return(400, "Invalid arguments")
    if method is 'DELETE':
        if len(args) < 1: return(400, "Invalid arguments")
        user_info = get_user_info(db, realm, user_name)
        if len(args) is 1:                                                                                  # Delete user
            if not user_info: return(404, "User not found")
            if delete_user(db, lock, user_name, realm=realm): return(200, "OK")
        return(400, "Invalid arguments")
    return(400, "Invalid request")

# Mostly lets 'admin' add and remove other admins
# But also lets admins change their secret
# usage:
#   GET /<default realm>/admins/                            -   List all system administrators
#   GET /<realm>/admins/                                    -   List all administrators of <realm>
#   PUT /<default realm>/admins/<new adminname>/<secret>    -   Creates a new adminstrator with password <secret>
#   PUT /<realm>/admins/<adminname>                         -   Adds <adminname> as an administrator of <realm>
#   DELETE /<default realm>/admins/<adminname>              -   Deletes <adminname> from the system
#   DELETE /<realm>/admins/<adminname>                      -   Removes <adminname> as an administrator of <realm>
#   PUT /<default realm>/admins/secret/<new secret>         -   Changes your secret to <new secret>
def admins (db, lock, method, realm, args, **kw):
    if method is 'GET':
        if len(args) is 0: return(200, "\n".join(list_admins(db, realm)))
        return(400, "Invalid arguments")
    if method is 'PUT':
        pass                                                # TODO: Implement me
    if method is 'DELETE':
        pass                                                # TODO: Implement me
    return(400, "Invalid request")

def certificates (db, lock, method, realm, args, **kw):
    return(200, "Certs")                                    # TODO: Implement me

# Allows an endpoint device (keypad) to register for a given realm
# Only one device allowed per realm
# usage:
#   GET /<realm>/register/                                  -   Registers calling device as accessor of <realm>, returns user code length
def register (db, lock, method, realm, args, **kw):
    if method is 'GET':
        print(kw['peercert'])
        return(200, str(USER_CODE_LENGTH))
    return(400, "Invalid request")

# And here's the machinery...
class RequestHandler(BaseHTTPRequestHandler):

    functions = {'auth':auth,'users':users,'admins':admins,'certificates':certificates,'register':register}
    read_realm = False
    write_realm = False
    admin = False

    # Here we hook the internal parse_request() method to set up some ground state
    # While we're here lets apply some hax so our server doesn't balk at spaces
    def parse_request(self, *args, **kwargs):
        raw_request = str(self.raw_requestline, 'iso-8859-1')                                                           #  .-----.
        request_path = raw_request[raw_request.index(' ')+1:raw_request.rindex(' ')]                                    # <  Hax |
        self.raw_requestline = raw_request.replace(request_path, request_path.replace(' ', '%20')).encode('iso-8859-1') #  '-----'
        return_to_caller = super().parse_request(*args, **kwargs)
        try:
            self.realm, self.function, self.args = parse_request_path(self.path)
        except ValueError:
            self.send_error(400, "Invalid function request")
            return False
        return(return_to_caller)


    def process_request(self, method):
        in_outer_realm = False
        realm, function, args = self.realm, self.function, self.args
        if not realm_exists(self.server.database, realm):
            if realm != self.server.default_realm:
                self.send_error(404, "No such realm")
                return
            else:
                in_outer_realm = True
        try:
            run_func = self.functions[function.lower()]
        except KeyError:
            self.send_error(400, "Invalid request")
            return
        code, message = run_func(self.server.database,
                                self.server.database_lock,
                                method,
                                None if in_outer_realm else realm.lower(),
                                [arg for arg in args],
                                peercert=self.connection.getpeercert())
        if int(str(code)[:1]) is 2:
            self.send_response(code)
            self.end_headers()
            try:
                self.wfile.write(bytes(message, 'utf-8'))
            except ssl.SSLEOFError:
                print("sslsocket: Premature EOF")     #TODO: Fix me
            self.wfile.write(bytes('\n', 'utf-8'))
        else:
            self.send_error(code, message)

    def do_GET(self):
        if self.check_auth('read_realm'): self.process_request('GET')

    def do_PUT(self):
        if self.check_auth('write_realm'): self.process_request('PUT')

    def do_DELETE(self):
        if self.check_auth('write_realm'): self.process_request('DELETE')

    def check_auth(self, permission):
        realm, function, args = self.realm, self.function, self.args
        admin_credentials = authorization_credentials(self.headers)
        if not admin_credentials:                                       # Most of the functionality can only be used by admins, so whitelist the things a non-admin can do
            if self.command != 'GET':
                self.send_error(403, "Access not allowed")                  #   non-admins can read-only
                return False
            if function == 'auth' and len(args) is 1: return True           #   non-admins can see if a user code is authorized for to access the realm
            if function == 'certificates' and len(args) is 0: return True   #   
            if function == 'register' and len(args) is 0: return True       #   non-admins (keypads) can register as gatekeepers of a realm
            self.send_error(403, "Access not allowed")
            return False
        if not self.authenticate_admin(realm, admin_credentials):
            self.send_error(403, "Access not allowed")
            return False
        check_permission = self.__dict__[permission]        # This check must be performed after authenticate_admin() has been called,
        if not check_permission:                            # since that function sets read_realm and write_realm as a side-effect
            self.send_error(403, "Access not allowed")
            return False
        return True

    def authenticate_admin(self, realm, admin_credentials):
        if not admin_credentials: return False
        admin_username, admin_password = admin_credentials
        query = "select * from admins where name = (?)"
        result = self.server.database.execute(query, [admin_username])
        row = result.fetchone()
        if not row: return False        # Potential timing attack for admin username discovery
        if row['secret'] == hash_password(admin_password, row['salt'])[0]:
            self.admin = True
            if admin_username == 'admin': # One admin to rule them all and in the darkness bind them
                self.read_realm = self.write_realm = True
                return True
            query = "select * from admin_acl where name = (?) and realm = (?)"
            result = self.server.database.execute(query, [admin_username, realm])
            row = result.fetchone()
            if row and (row['read'] or row['write']):
                self.read_realm, self.write_realm = row['read'], row['write']
                return True
            return False

    def version_string(self):
        if self.admin: return("Cookie crisp!")
        return("YOU SHALL NOT PASS!")

# Some convenience functions...
def authorization_credentials (headers):
    if not headers['Authorization']: return False
    auth_type, encoded_auth_string = headers['Authorization'].split(' ')
    return base64.b64decode(encoded_auth_string).decode('utf-8').split(':')

def daemonize(fun, *args, **kwargs):
    thread = threading.Thread(target=fun, args=args, kwargs=kwargs, daemon=True)
    thread.start()

def generate_ssl_cert(country_name=None, state_name=None, locality_name=None, org_name=None, unit_name=None, common_name=None, email_address=None, hush=True):
    def openssl(*args):
        command = [OPENSSL_PATH] + list(args)
        subprocess.check_call(command, stderr=subprocess.DEVNULL) if hush else subprocess.check_call(command)
    field = lambda s, f: "/{0}={1}".format(s, f) if f else ""
    subject = field('C', country_name)
    subject += field('ST', state_name)
    subject += field('L', locality_name)
    subject += field('O', org_name)
    subject += field('OU', unit_name)
    subject += field('CN', common_name)
    subject += field('emailAddress', email_address)
    cert_path = temporary_path()
    key_path = temporary_path()
    openssl('req', '-new', '-x509', '-nodes', '-out', cert_path, '-keyout', key_path, '-subj', subject)
    with open(cert_path, 'r') as cert_file: cert=cert_file.read()
    os.remove(cert_path)
    with open(key_path, 'r') as key_file: key=key_file.read()
    os.remove(key_path)
    return cert, key

def get_cert_expiration(cert_data):
    # Solution borrowed from: https://kyle.io/2016/01/checking-a-ssl-certificates-expiry-date-with-python/
    from OpenSSL import crypto
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    return(datetime.datetime.strptime(cert.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ"))

def hash_password(password, salt=secrets.token_urlsafe(32)):
    password_hash = base64.b64encode(hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(salt, 'utf-8'), 200000))
    return (password_hash, salt)

def locked_query(db, lock, query, *args):
    lock.acquire()
    result = db.execute(query, args)
    db.commit()
    lock.release()
    return result

def make_boolean(bool_string):
    if bool_string.lower() in ['yes', 'y', 'true', 't', '1']: return True
    return False

def normalize_nested_list(nested_list):
    normalized_list = list()
    for row in nested_list:
        normalized_list.append(", ".join(map(str, row)))
    return(normalized_list)

# Requests must be in the form of /<realm>/<function>/[optional/arguments]
def parse_request_path (path):
    realm, function, *arguments = [s for s in path.split("/") if s is not '']
    return realm.lower(), function, arguments

def temporary_path(contents=None):
    handle, path = tempfile.mkstemp()
    if contents: os.write(handle, bytes(contents, 'utf-8'))
    os.close(handle)
    return path

def valid_date(date_string):
    try:
        datetime.datetime.strptime(date_string, '%Y-%m-%d')
    except ValueError:
        return False
    return True

# Database manipulation...
def save_certificate(db, hostname, certificate, lock=None):
    query = "insert into ssl_certs (hostname, certificate) values ((?), (?))"
    if lock:
        locked_query(db, lock, query, hostname, certificate)
    else:
        db.execute(query, [hostname, certificate])

def delete_certificate(db, hostname, lock=None):
    query = "delete from ssl_certs where hostname = (?)"
    if lock:
        locked_query(db, lock, query, hostname)
    else:
        db.execute(query, [hostname])

def get_certificate(db, hostname, cert_only=True):
    query = "select certificate from ssl_certs where hostname = (?)"
    result = db.execute(query, [hostname])
    row = result.fetchone()
    if not row: return None
    if cert_only: return row['certificate'][row['certificate'].find("-----BEGIN CERTIFICATE-----"):row['certificate'].rfind("-----END CERTIFICATE-----")+25]
    else: return row['certificate']

def realm_exists(db, realm):
    query = "select 1 from sqlite_master where type = 'table' and name = ?"
    return db.execute(query, ["{0}_users".format(realm)]).fetchone() is not None

def generate_user_code(db):
    potential_code = random.randint(0,(10**USER_CODE_LENGTH)-1)
    query = "select name from users where code = (?)"
    if db.execute(query, [potential_code]).fetchone(): return(generate_user_code(db))
    return(potential_code)

def get_user_code(db, user_name):
    query = "select code from users where name = (?)"
    return db.execute(query, [user_name]).fetchone()

def check_user_auth(db, code, realm):
    retval = False
    if realm is None: return retval
    query = "select name from users where code = (?)"
    result = db.execute(query, [code])
    row = result.fetchone()
    if row:
        query = "select * from {0}_users where name = ?".format(realm)
        if db.execute(query, [row['name']]).fetchone() is not None: return row['name']
    return retval

def log_access(db, lock, realm, name):
    now = datetime.datetime.utcnow()
    query = "insert into accesslog values ((?), (?), (?))"
    daemonize(locked_query, db, lock, query, now, realm, name)
    query = "update {0}_users set lastused = (?) where name = (?)".format(realm)
    daemonize(locked_query, db, lock, query, now, name)

def list_users(db, realm):
    query = "select name from {0}_users".format(realm) if realm else "select name from users"
    result = db.execute(query)
    return [row['name'] for row in result]

def admin_list_users(db, realm):
    query = "select name, lastused from {0}_users".format(realm) if realm else "select name, comment, created, expires, uses, rentdue, frozen from users"
    result = db.execute(query)
    return [[col for col in row] for row in result]

def list_admins(db, realm):
    query="select name from admin_acl where realm == (?)" if realm else "select name from admins"
    result = db.execute(query, [realm]) if realm else db.execute(query)
    return [row['name'] for row in result]

def get_user_info(db, realm, user_name):
    if realm is None:
        query = "select comment, created, expires, uses, rentdue, frozen from users where name = (?)"
    else:
        query = "select lastused from {0}_users where name = (?)".format(realm)
    return db.execute(query, [user_name]).fetchone()

def create_user(db, lock, name, realm=None):
    code = generate_user_code(db)
    query = "insert into users (code, name, created) values (?, ?, ?)"
    locked_query(db, lock, query, code, name, datetime.date.today())
    if realm: add_user_to_realm(db, lock, name, realm)
    return code

def delete_user(db, lock, name, realm=None):
    def cleanup_realms(realm_tables):
        for realm_table in realm_tables:
            query = "delete from {0} where name = (?)".format(realm_table)
            locked_query(db, lock, query, name)

    query = "delete from {0} where name = (?)".format("{0}_users".format(realm) if realm else "users")
    locked_query(db, lock, query, name)
    if not realm:
        query = "select tbl_name from sqlite_master where type = 'table' and tbl_name like '%_users' escape '_'"
        result = db.execute(query)
        daemonize(cleanup_realms, [row['tbl_name'] for row in result])
    return True

def add_user_to_realm(db, lock, name, realm):
    if not realm: return False
    query = "insert into {0}_users (name) values (?)".format(realm)
    locked_query(db, lock, query, name)
    return True

def update_user(db, lock, name, field, value):
    if field == 'expires' and not valid_date(value): return False
    if field == 'comment': value = value.replace('%20', ' ')
    if field == 'rentdue' or field == 'frozen': value = make_boolean(value)
    query = "update users set {0} = ? where name = (?)".format(field)
    locked_query(db, lock, query, value, name)
    return True

def setup(db, realm):
    db.executescript(DATABASE_SCHEMA)
    db.executescript(TESTDATA)          # REMOVE ONLY FOR TESTING
    admin_secret = secrets.token_urlsafe(16)
    print("\033[1m\033[93mAdmin secret:\033[0m\033[1m {0}\033[0m".format(admin_secret))
    query = "insert into admins (name, secret, salt) values ('admin', (?), (?));"
    db.execute(query, hash_password(admin_secret))
    query = "insert into admin_acl (name, realm, read, write) values ('admin', (?), 1, 1);"
    db.execute(query, [realm])
    db.commit()

def cleanup(db):
    db.close()

sqlite3.register_converter('bool', lambda x: True if int(x) is 1 else False)
sqlite3.register_adapter('bool', lambda x: 1 if x is True else 0)

DATABASE_SCHEMA = """
create table admins (
    name        text primary key,
    secret      text not null,
    salt        text not null
);

create table admin_acl (
    name        text not null,
    realm       text not null collate nocase,
    read        bool not null default 1,
    write       bool not null default 0
);

create table users (
    code        integer primary key not null,
    name        text not null collate nocase,
    comment     text,
    created     date not null,
    expires     date,
    uses        integer not null default -1,
    rentdue     bool not null default 0,
    frozen      bool not null default 0
);

create table accesslog (
    timestamp   timestamp not null,
    realm       text not null collate nocase,
    name        text not null default 'Someone' collate nocase
);

create table ssl_certs (
    hostname    text not null primary key collate nocase,
    certificate text not null
);
"""

TESTDATA = """
create table gate_users (
    name        text not null primary key collate nocase,
    lastused    datetime
);

create table pfaff_users (
    name        text not null primary key collate nocase,
    lastused    datetime
);

insert into users values(123456, 'tom', 'wha', '2012-12-25', '2012-12-25', -1, 0, 0);
insert into users values(111111, 'sue', 'wha', '2012-12-25', '2012-12-25', -1, 0, 0);
insert into users values(654321, 'tim', 'wha', '2012-12-25', '2012-12-25', -1, 0, 0);

insert into gate_users values ('tom', '2012-12-25 23:59:59');
insert into gate_users values ('tim', '2012-12-25 23:59:59');
insert into pfaff_users values ('sue', '2012-12-25 23:59:59');
"""



if __name__ == '__main__':
    argument_parser = argparse.ArgumentParser(add_help=False)
    noisy_options = argument_parser.add_mutually_exclusive_group()
    noisy_options.add_argument('-q', '--quiet', action='store_true')
    noisy_options.add_argument('-v', '--verbose', action='store_true')
    ssl_options = argument_parser.add_mutually_exclusive_group()
    ssl_options.add_argument('-c', '--cert-file')
    ssl_options.add_argument('-n', '--no-ssl', action='store_true')
    argument_parser.add_argument('-k', '--key-file')
    argument_parser.add_argument('-r', '--realm')
    argument_parser.add_argument('-h', '--host', default='localhost')
    argument_parser.add_argument('-p', '--port')
    args = argument_parser.parse_args()
    if args.key_file and not args.cert_file: argument_parser.error("You must specify a certificate file (use --cert-file <path/to/certificate.pem>)")
    main(args)

