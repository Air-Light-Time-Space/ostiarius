import errno
import gc
import micropython
import urequests

from uhashlib import sha256
from ubinascii import hexlify

from configuration import Configuration

class Authorization ():

    def __init__(self, config=Configuration(), status_led=None):
        self.led = status_led
        self.config = config
        self.is_registered = False
        self.server_status = "UNREGISTERED"

    def build_auth_uri(self, action):
        return("https://{:s}:{:d}/{:s}/{:s}".format(self.config.AUTH_SERVER.split(":")[0],
                                                    self.config.AUTH_PORT,
                                                    self.config.AUTH_REALM,
                                                    action))

    def fetch_response(self, uri, send_cert=True):
        gc.collect()
        if not self.config.AUTH_SERVER:
            return False
        try:
            if send_cert:
                return(urequests.get(uri, cert=("public.cert", "private.key")))
            else:
                return(urequests.get(uri))
        except OSError as e:
            if e.args[0] == errno.EIO and send_cert:
                if self.config.DEBUG: print("fetch_response: SSL handshake error, retrying without cert")
                return(self.fetch_response(uri, send_cert=False))
            if e.args[0] == errno.EHOSTUNREACH:
                self.server_status = "AUTH SERVER UNREACHABLE"
            else:
                self.server_status = str(e)
            return False
  #      except ValueError as e:
  #          print(e)
  #          return False

    def check_fingerprint(self, fingerprint):
        if self.config.AUTH_SERVER_FINGERPRINT is None:
            self.config.AUTH_SERVER_FINGERPRINT = fingerprint
            self.config.write()
            print("Auth fingerprint: {:s}".format(fingerprint))
        else:
            if fingerprint != self.config.AUTH_SERVER_FINGERPRINT:
                self.server_status = "BAD PEER CERT"
                return False
        return True

    def register(self):
        auth_uri = self.build_auth_uri("register")
        if self.config.DEBUG: print("register: auth_uri: {:s}".format(auth_uri))

        response = self.fetch_response(auth_uri)
        if response is False:
            return False

        peer_fingerprint = hash_cert(response.raw.getpeercert(True))
        if not self.check_fingerprint(peer_fingerprint):
            if self.config.DEBUG is True:
                print("register: Registration failed, bad peer cert")
                print("(expected fingerprint: {:s}, actual fingerprint({:s})".format(self.config.AUTH_SERVER_FINGERPRINT, peer_fingerprint))
            return False

        if response.status_code == 200:
            self.server_status = "OK"
            if self.config.DEBUG is True: print("register: Registration succesful, (peer fingerprint: {:s})".format(peer_fingerprint))
            try:
                new_code_len = int(response.text)
            except Exception as e:
                print(e)
                print("Non-numeric registration")
            if self.config.CODE_LENGTH != new_code_len:
                if self.config.DEBUG: print("register: Setting CODE_LENGTH to {:d}".format(new_code_len))
                self.config.CODE_LENGTH = new_code_len
                self.config.write()
            return True
        else:
            self.server_status = "NOT OK"
        response.close()

    def check_code(self, code):
        auth_uri = self.build_auth_uri("auth/{:s}".format(code))
        if self.config.DEBUG: print("check_code: auth_uri: {:s}".format(auth_uri))

        if self.led: self.led.enable(self.led.YELLOW)
        response = self.fetch_response(auth_uri)
        if response is False:
            if self.led: self.led.pulse(self.led.RED, 3)
            return False

        peer_fingerprint = hash_cert(response.raw.getpeercert(True))
        if not self.check_fingerprint(peer_fingerprint):
            if self.config.DEBUG is True:
                print("check_code: Authorization check failed, bad peer cert")
                print("(expected fingerprint: {:s}, actual fingerprint{:s})".format(self.config.AUTH_SERVER_FINGERPRINT, peer_fingerprint))
            return False

        if response.status_code == 200:
            if self.led: self.led.pulse(self.led.GREEN, 3)
            return True
        else:
            if self.led: self.led.pulse(self.led.RED, 3)
            return False
        response.close()

# Creates a "fingerprint" of the DER encoded peer certificate
def hash_cert(der_cert):
    o = sha256()
    o.update(der_cert)
    return(hexlify(o.digest()).decode())


import usocket
import ussl
Response = urequests.Response

# Here we've copied and pasted the request function from https://github.com/pfalcon/micropython-lib/blob/master/urequests/urequests/__init__.py
# and modified it to accept a keyword argument "cert" which takes a tuple of ("path/to/public/cert", "path/to/private/key") and attempts to use
# the specified credentials as a client certificate during ssl handshake
def request_with_ssl_cert_patch(method, url, data=None, json=None, headers={}, stream=None, parse_headers=True, cert=None):
    redir_cnt = 1
    if json is not None:
        assert data is None
        import ujson
        data = ujson.dumps(json)

    while True:
        try:
            proto, dummy, host, path = url.split("/", 3)
        except ValueError:
            proto, dummy, host = url.split("/", 2)
            path = ""
        if proto == "http:":
            port = 80
        elif proto == "https:":
            import ussl
            port = 443
        else:
            raise ValueError("Unsupported protocol: " + proto)

        if ":" in host:
            host, port = host.split(":", 1)
            port = int(port)

        ai = usocket.getaddrinfo(host, port, 0, usocket.SOCK_STREAM)
        ai = ai[0]

        resp_d = None
        if parse_headers is not False:
            resp_d = {}

        s = usocket.socket(ai[0], ai[1], ai[2])
        try:
            s.connect(ai[-1])
            if proto == "https:":
                if cert is not None:                                        # Here's the patch
                    key = open(cert[1])
                    cert = open(cert[0])
                    s = ussl.wrap_socket(s, server_hostname=host, cert=cert.read(), key=key.read())
                    cert.close()
                    key.close()
                else:
                    s = ussl.wrap_socket(s, server_hostname=host)
            s.write(b"%s /%s HTTP/1.0\r\n" % (method, path))
            if not "Host" in headers:
                s.write(b"Host: %s\r\n" % host)
            # Iterate over keys to avoid tuple alloc
            for k in headers:
                s.write(k)
                s.write(b": ")
                s.write(headers[k])
                s.write(b"\r\n")
            if json is not None:
                s.write(b"Content-Type: application/json\r\n")
            if data:
                s.write(b"Content-Length: %d\r\n" % len(data))
            s.write(b"Connection: close\r\n\r\n")
            if data:
                s.write(data)

            l = s.readline()
            #print(l)
            l = l.split(None, 2)
            status = int(l[1])
            reason = ""
            if len(l) > 2:
                reason = l[2].rstrip()
            while True:
                l = s.readline()
                if not l or l == b"\r\n":
                    break
                #print(l)

                if l.startswith(b"Transfer-Encoding:"):
                    if b"chunked" in l:
                        raise ValueError("Unsupported " + l)
                elif l.startswith(b"Location:") and 300 <= status <= 399:
                    if not redir_cnt:
                        raise ValueError("Too many redirects")
                    redir_cnt -= 1
                    url = l[9:].decode().strip()
                    #print("redir to:", url)
                    status = 300
                    break

                if parse_headers is False:
                    pass
                elif parse_headers is True:
                    l = l.decode()
                    k, v = l.split(":", 1)
                    resp_d[k] = v.strip()
                else:
                    parse_headers(l, resp_d)
        except OSError:
            s.close()
            raise

        if status != 300:
            break

    resp = Response(s)
    resp.status_code = status
    resp.reason = reason
    if resp_d is not None:
        resp.headers = resp_d
    return resp

# Here we monkey-patch our modified function back into the urequests namespace
urequests.request = request_with_ssl_cert_patch

################################################################################

def main():
    pass # TODO: Write tests

if __name__ == '__main__':
    main()

run = main
