import errno
import os
import select
import socket
import ssl
import machine
import micropython
import gc
import sys

import uasyncio as asyncio

from utarfile import TarFile
from ubinascii import b2a_base64
from ubinascii import hexlify
from uhashlib import sha256

from main import version as fw_version

# This slapdash diy web server is the most convoluted, memory-hogging, likely bug-ridden
# module in this project. It should probably be used at most once to initially configure
# the device and then disabled. It is necessary to run this module for remote latch
# triggering to work, but it tries to run as stripped down as possible if config.DISABLE_ADMIN
# is also set.
class WebAdmin():

    def __init__(self, config, key=None, cert=None, connections=10):
        if config.DEBUG: print(gc.mem_free())
        gc.collect()
        if config.DEBUG: print(gc.mem_free())
        self.config = config
        self.key = key
        self.cert = cert

        if not config.DISABLE_ADMIN:
            self.active_token = None

            ip_addr = config.WLAN_IP if config.WLAN_IP else config.PHYS_IP
            subnet = config.WLAN_SUBNET if config.WLAN_IP else config.PHYS_SUBNET
            gateway = config.WLAN_GATEWAY if config.WLAN_IP else config.PHYS_GATEWAY
            dns = config.WLAN_DNS if config.WLAN_IP else config.PHYS_DNS
            self.config_subs = {    # Substitution map for config.html:
                "@USE_ETHER_CHECK": "checked=checked" if config.PHYS_IP else "",
                "@USE_WIFI_CHECK": "checked=checked" if config.WLAN_IP else "",
                "@WIFI_SSID": config.WLAN_SSID or "" if config.WLAN_IP else "",
                "@WIFI_PASS": config.WLAN_PASS or "" if config.WLAN_IP else "",
                "@IP_ADDR": ip_addr or "" if ip_addr != "Auto" else "",
                "@USE_DHCP": "checked=checked" if ip_addr == "Auto" else "",
                "@SUBNET": subnet or "" if ip_addr != "Auto" else "",
                "@GATEWAY": gateway or "" if ip_addr != "Auto" else "",
                "@DNS": dns or "" if ip_addr != "Auto" else "",
                "@AUTH_SERVER": config.AUTH_SERVER or "",
                "@REALM": config.AUTH_REALM or "",
                "@UNLATCH_DURATION": str(config.UNLATCH_DURATION),
                "@REMOTE_UNLATCH_CHECK": "checked=checked" if config.ALLOW_REMOTE_UNLATCH is True else "",
                "@AUX_A": config.AUX_A or "",
                "@AUX_B": config.AUX_B or "",
                "@AUX_C": config.AUX_C or "",
                "@AUX_D": config.AUX_D or "",
                "@DISABLE_ADMIN_CHECK": "checked=checked" if config.AUTH_SERVER is None else "",
            }

            self.status_subs = {    # substitution map for status.html:
                "@MEM_USED": str(gc.mem_alloc()),
                "@MEM_FREE": str(gc.mem_free()),
                "@MACHINE": os.uname()[0],
                "@SYS_VERSION": " for ".join(["-".join([sys.implementation[0], os.uname()[3]]), os.uname()[0]]),
                "@FW_VERSION": fw_version
            }

            self.http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.http_sock.bind(('', 80))
            self.http_sock.listen(connections)

            if config.ADMIN_PASS is None:
                self.server_context = self.serve_initial_login
            else:
                self.server_context = self.serve_admin_dashboard
        else:
            self.server_context = self.serve_remote_latch_interface

        if key and cert:
            self.https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.https_sock.bind(('', 443))
            self.https_sock.listen(connections)

        if config.DEBUG:
            print(gc.mem_free())

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def get_mime(self, filename):
        # A rather brute approach
        name, ext = filename.rsplit(".", 1)
        # Not exhaustive...
        if ext == "html" or ext == "htm": return("text/html")
        if ext == "txt": return("text/plain")
        if ext == "css": return("text/css")
        if ext == "js": return("text/javascript")
        if ext == "png": return("image/png")
        return("text/html") # Not the most secure default stance, better to error?

    def serve_file(self, filename, connection, token=None, substitutions=None):
        try:
            f = open(filename, 'r')
        except OSError:
            self.serve_404(connection)
            return False
        print(" -> 200 - serving {:s}".format(filename))
        connection.write("HTTP/1.1 200 OK\nConnection: close\nServer: kpdadm\nContent-Type: {:s}{:s}\n\n".format(self.get_mime(filename),
                        "\nSet-Cookie: token={:s}".format(token) if token else ""))
        for line in f:
            if substitutions:
                for pattern, substitute in substitutions.items():
                    line = line.replace(pattern, substitute)
            connection.write(line)
        connection.write('\n')
        connection.close()
        gc.collect() # This is crucial when using ssl or we can run out of memory during the next handshake   
        return True

    def serve_404(self, connection):
        print(" -> 404 - resource not found")
        connection.write("HTTP/1.1 404 NOT FOUND\nConnection: close\nServer: kpdadm\nContent-Type: text/plain\n\nResource not found\n\n")
        connection.close()

    def check_token(self, request):
    # We only suport one login at a time, if we wanted to support more
    # we could put active_tokens in a list, but why?
        if 'token' in request.cookies:
            if request.cookies['token'] == self.active_token:
                return True
        else:
            print("Invalid token presented")
        return False

    def serve_admin_dashboard (self, request):
        conn = request.socket

        if request.type == 'POST' and 'password' in request.args.keys():                # This check should stay at the top
            with open("salt", 'r') as f:
                salt = f.read()
                f.close()
            if hashpass(request.args['password'], salt, machine.unique_id()) == self.config.ADMIN_PASS:
                self.active_token = str(b2a_base64(os.urandom(512)))[:-4]
                self.serve_file("config.html", conn, token=self.active_token, substitutions=self.config_subs)
                return
            else:
                self.serve_file("badlogin.html", conn)
            return

        if not self.check_token(request):                                               # And this should be the second from top
            self.serve_file("login.html", conn)
            return
                                                                                        # The order of the rest doesn't matter
        if request.resource == "/logout":
            self.active_token = None
            self.serve_file("login.html", conn)
            return

        if request.resource == "/status":
            self.status_subs['@UPDATE_ACTION@'] = "http://{:s}/update".format(request.header['host'])
            self.serve_file("status.html", conn, substitutions=self.status_subs)
            return

        if request.resource == "/update":       # See listen_http
            # ussl.wrap_socket crashes with "mbedtls_ssl_handshake error: -7d00" when we try to upload large files, 
            # (> 1500 bytes) so we upload over http instead and verify checksum
            # 96: #define MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS     -0x7D00
            # Possibly related to https://www.digi.com/support/forum/70247/ussl-wrap_socket-truncates-sent-data
            self.serve_404(conn)
            return

        if request.resource == "/config" or request.resource == "/":
            # We are doing very little validation or sanity checking, interface for use by careful administrators only
            if request.type == "POST":
                if request.args["connect"] == "use_wifi" and "wlan_ssid" not in request.args:
                    self.serve_file("badconfig.html", conn, substitutions={"@REASON": "No wifi ssid set"})
                    return
                if "use_dhcp" not in request.args and not {"ip_address", "subnet"}.issubset(request.args):
                    self.serve_file("badconfig.html", conn, substitutions={"@REASON": "Invalid network configuration"})
                    return
                if "auth_server" not in request.args:
                    self.serve_file("badconfig.html", conn, substitutions={"@REASON": "No auth server set"})
                    return
                if "realm" not in request.args:
                    self.serve_file("badconfig.html", conn, substitutions={"@REASON": "No realm set"})
                    return
                if {"newpw", "pwconf"}.issubset(request.args):
                    if request.args["newpw"] != request.args["pwconf"]:
                        self.serve_file("badconfig.html", conn, substitutions={"@REASON": "Passwords do not match"})
                        return

                # Set configuration...
                self.serve_file("reboot.html", conn)
                if request.args["connect"] == "use_wifi":
                    self.config.WLAN_SSID = request.args["wlan_ssid"]
                    self.config.WLAN_PASS = request.args["wlan_pass"] if "wlan_pass" in request.args else ""
                    if "use_dhcp" in request.args:
                        self.config.WLAN_IP = "Auto"
                    else:
                        self.config.WLAN_IP = request.args["ip_address"]
                        self.config.WLAN_SUBNET = request.args["subnet"]
                        self.config.WLAN_GATEWAY = request.args["gateway"] if "gateway" in request.args else None
                        self.config.WLAN_DNS = request.args["dns"] if "dns" in request.args else None
                    self.config.PHYS_IP = None
                else:
                    if "use_dhcp" in request.args:
                        self.config.PHYS_IP = "Auto"
                    else:
                        self.config.PHYS_IP = request.args["ip_address"]
                        self.config.PHYS_SUBNET = request.args["subnet"]
                        self.config.PHYS_GATEWAY = request.args["gateway"] if "gateway" in request.args else None
                        self.config.PHYS_DNS = request.args["dns"] if "dns" in request.args else None
                    self.config.WLAN_IP = None
                self.config.AUTH_SERVER = request.args["auth_server"]
                self.config.AUTH_REALM = request.args["realm"]
                if "unlatch_duration" in request.args: self.config.UNLATCH_DURATION = int(request.args["unlatch_duration"])
                if "aux_a" in request.args: self.config.AUX_A = request.args["aux_a"]
                if "aux_b" in request.args: self.config.AUX_B = request.args["aux_b"]
                if "aux_c" in request.args: self.config.AUX_C = request.args["aux_c"]
                if "aux_d" in request.args: self.config.AUX_D = request.args["aux_d"]
                if "newpw" in request.args: self.config.ADMIN_PASS = hashpass(request.args["newpw"], make_salt(), machine.unique_id())
                self.config.DISABLE_ADMIN = True if "disable_admin" in request.args else False
                self.config.ALLOW_REMOTE_UNLATCH = True if "remote_unlatch" in request.args else False
                self.config.write()
                machine.reset()
                return
            else:
                self.serve_file("config.html", conn, substitutions=self.config_subs)
                return

        # Default response
        self.serve_404(conn)
        return

    def serve_initial_login (self, request):
        conn = request.socket

        if request.resource == "/":
            self.serve_file("newuser.html", conn)
            return

        if request.resource == "/hello":
            if request.type == "POST":
                if {"newpw", "pwconf"}.issubset(request.args):
                    if request.args["newpw"] == request.args["pwconf"]:
                        self.serve_file("reboot.html", conn)
                        self.config.ADMIN_PASS = hashpass(request.args["newpw"], make_salt(), machine.unique_id())
                        self.config.write()
                        machine.reset()
                        return
                self.serve_file("pwmismatch.html", conn)
                return

        # Default response
        self.serve_404(conn)
        return

    def serve_remote_latch_interface (self, request):                     #TODO: Implement

        # Default response
        self.serve_404(conn)
        return

    # It would be nice if this didn't block, but internal politics of micropython prevent us from
    # using the latest uasyncio (which we need to implement non-blocking ssl) and supporting
    # stock micropython at the same time
    async def listen_https (self):
        if self.key is None or self.cert is None: return False
        poller = select.poll()
        poller.register(self.https_sock, select.POLLIN)
        while self.running:
            event = poller.poll(1)  # blocks for 1ms
            if event:
                gc.collect()
                try:
                    conn, (ipaddr, port) = self.https_sock.accept()
                except OSError as e:
                    if self.config.DEBUG: print("listen_https: Couldn't open socket: {:s}".format(err_reason(e)))
                    continue
                try:
                    key = open(self.key)
                    cert = open(self.cert)
                    sock = ssl.wrap_socket(conn, key=key.read(), cert=cert.read(), server_side=True)
                    cert.close()
                    key.close()
                except OSError as e:
                    if self.config.DEBUG: print("listen_https: Couldn't wrap socket: {:s}".format(err_reason(e)))
                    conn.close()
                    continue
                try:
                    request = httpRequest(sock)
                except ValueError as e:
                    if self.config.DEBUG: print("listen_https: Couldn't fulfill request: {:s}".format(err_reason(e)))
                    continue
                except OSError as e:
                    if self.config.DEBUG: print("listen_https: Couldn't fulfill request: {:s}".format(err_reason(e)))
                    conn.close()
                    continue
                print("{:s}:{:d} - {:s} {:s}".format(ipaddr, port, request.type, request.resource))
                self.server_context(request)
            await asyncio.sleep_ms(0)

    # Redirect unencrypted http requests to https
    async def listen_http (self):
        poller = select.poll()
        poller.register(self.http_sock, select.POLLIN)
        while self.running:
            event = poller.poll(1)  # blocks for 1ms
            if event:
                gc.collect()
                try:
                    conn, (ipaddr, port) = self.http_sock.accept()
                except OSError as e:
                    if self.config.DEBUG: print("listen_http: Couldn't open socket: {:s}".format(err_reason(e)))
                    continue
                try:
                    request = httpRequest(conn)
                except ValueError as e:
                    if self.config.DEBUG: print("listen_http: Couldn't fulfill request: {:s}".format(err_reason(e)))
                    conn.close()
                    continue
                except OSError as e:
                    if self.config.DEBUG: print("listen_http: Couldn't fulfill request: {:s}".format(err_reason(e)))
                    conn.close()
                    continue
                print("{:s}:{:d} - {:s} {:s}".format(ipaddr, port, request.type, request.resource))
                if self.key is None or self.cert is None:
                    self.serve_file("misconfigured.html", conn)
                    continue
                if (request.resource == "/update"):
                    if request.type == "POST":
                        gc.collect()
                        # Check for admin cookie
                        if not self.check_token(request):
                            self.serve_404(conn)
                            continue
                        else:                           # Token has been sent in the clear, so invalidate it and make them log in again
                            self.active_token = None    # the device reboots on the happy path anyway

                        # Someone could send an arbitrary file (say, "boot.py") and forge the request headers and 
                        # probably defeat these simple checks, but we made them authenticate as an administrator
                        # already so we're not going to worry too much about it
                        subs = { "@HOST": request.header['host'] }
                        if hasattr(request, "error"):
                            subs["@REASON"] = request.error
                            self.serve_file("badupload.html", conn, substitutions=subs)
                            continue
                        if "application/x-tar" != request.args["Content-Type"]:
                            subs["@REASON"] = "Invalid firmware file format."
                            self.serve_file("badupload.html", conn, substitutions=subs)
                            os.remove(request.filename)
                            continue
                        os.rename(request.filename, "/firmware/{:s}".format(request.args["filename"]))
                        update_success, message = update_firmware("/firmware/{:s}".format(request.args["filename"]))
                        if not update_success:
                            subs["@REASON"] = message
                            self.serve_file("badupload.html", conn, substitutions=subs)
                            continue     
                        self.serve_file("reboot.html", conn)
                        machine.reset()
                        continue
                    else:
                        self.serve_404(conn)
                        continue
                else:
                    conn.write("HTTP/1.1 302 FOUND\nLocation: https://{:s}\nConnection: close\nServer: kpdadm\n\n".format(self.config.interface.ifconfig()[0]))
                    conn.close()
                    print(" -> 302 - redirect to https://{:s}".format(self.config.interface.ifconfig()[0]))
            await asyncio.sleep_ms(0)

class httpRequest():

    def __init__(self, conn):
        self.socket = conn
        self.args = dict()
        self.header = dict()
        self.cookies = dict()

        self.type, self.resource, self.proto = conn.readline().decode().split()

        while True:
            line = conn.readline().decode().strip()
            if line == '':
                break
            t = line.split(':')
            self.header[t[0].lower()] = t[1].strip()

        if 'cookie' in self.header.keys():
            c = [s2 for s1 in self.header['cookie'].split('=') for s2 in s1.split(';')]
            self.cookies = dict(zip(c[0::2], c[1::2]))

        if 'content-length' in self.header.keys():
            body = b''
            if 'content-type' in self.header.keys():
                # This is implemented as more of a singlepart/form-data because that's all we really need
                if self.header['content-type'].startswith("multipart/form-data"):
                    boundary = self.header['content-type'].split(";")[1][10:]
                    bytes_left = int(self.header['content-length'])     # TODO: Reject file upload if larger than available storage (os.statvfs)
                    boundary_start = conn.readline()
                    if '--{:s}'.format(boundary) not in boundary_start.decode():
                        self.error = ("Boundary mismatch")
                        conn.read(bytes_left - len(boundary_start))
                    else:
                        bytes_left -= len(boundary_start)
                        line = b''
                        while line != b'\r\n':
                            line = conn.readline()
                            body = b''.join([body, line])
                        bytes_left -= len(body)
                        filename = "/tmp/{:s}".format(b2a_base64(os.urandom(12)).decode().strip())
                        with open(filename, 'wb') as f:
                            while bytes_left > len(boundary_start):
                                read_len = min(512, bytes_left - len(boundary_start))
                                f.write(conn.read(read_len))
                                bytes_left -= read_len
                            f.close()
                        boundary_end = conn.read(len(boundary_start))
                        if '{:s}--'.format(boundary) not in boundary_end.decode().strip():
                            self.error = ("Boundary mismatch")
                            os.remove(filename)
                        else:
                            self.filename = filename          
                else:
                    body = conn.read(int(self.header['content-length']))    # TODO: Implement large payload rejection (http 413) so
                                                                            # attackers can't DOS system memory with large requests
        if 'POST' in self.type:
            self.args = dict()
            args = body.decode().strip().replace("\r\n", ";").replace(": ", "=").replace('"', "") # Yikes!
            pairs = [s2 for s1 in args.split('&') for s2 in s1.split(';')]

            for name_value in pairs:
                nv = name_value.split('=', 1)
                if len(nv) != 2:
                    nv.append('')
                if len(nv[1]):
                    name = nv[0].replace('+', ' ')
                    value = nv[1].replace('+', ' ')
                    self.args[name.strip()] = value.strip()

def err_reason(err_code):
    try:
        return(errno.errorcode[err_code])
    except KeyError:
        return("Unknown error code: {:s}".format(str(err_code)))

# TODO: Sign checksums file, otherwise entire upload can easily be forged in transit
def update_firmware(filename):

    gc.collect()
    print(micropython.mem_info())

    update = TarFile(filename)
    checksums_file = None
    print(micropython.mem_info())
    for tf in update:
        if tf.name == "checksums.txt":
            checksums_file = update.extractfile(tf).read()
    print(micropython.mem_info())
    if checksums_file is None:
        return False, "Could not validate checksums"
    else:
        checksums = {}
        for ck in checksums_file.strip().split(b"\n"):
            ckname, cksum = ck.decode().split(" ")
            checksums[ckname] = cksum

    gc.collect()

    update = TarFile(filename)
    for tf in update:
        if tf.name != "checksums.txt":
            if make_checksum(update.extractfile(tf)) != checksums[tf.name]:
                gc.collect()
                os.remove(filename)
                return False, "Could not validate checksums"

    gc.collect()

    print("Updating firmware from file: {:s}".format(filename))
    update = TarFile(filename)
    for tf in update:
        with open(tf.name, "wb") as f:
            buf = bytearray(1024)
            fileobj = update.extractfile(tf)
            while True:
                buf = fileobj.read(1024)
                f.write(buf)
                if len(buf) < 1024:
                    break

    gc.collect()
    return True, None

def make_checksum (fileobj):
    block = bytearray(512)
    checksum = sha256()
    while True:
        block = fileobj.read(512)
        checksum.update(block)
        if len(block) < 512:
            break
    return(hexlify(checksum.digest()).decode())

# This function hashes a password for local storage. Salt and pepper is kind of silly
# because if anyone has the hashed password they probably own the device, and sha256
# has no protection against brute force attacks. Credentials should probably be secured
# by encrypted flash and trusted boot process and this code should probably not be
# re-used in other environments.
def hashpass(password, salt, pepper=None):
    passhash = sha256(salt)
    passhash.update(password)
    if pepper:
        passhash.update(pepper)
    return str(passhash.digest())

def make_salt ():
    salt = str(b2a_base64(os.urandom(512)))[:-4]
    with open("salt", 'w') as f:
        f.write(salt)
        f.close()
    return salt

################################################################################

def main():
    import micropython
    import configuration
    import connection

    testkey = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDNu6St4SwBfxOd
FAauI5LUIcjO6FTcJPzcn581hvNiHLHqJJE4Nwe5IAOyR1JnxwuEw0KqGOk2ox2h
fRO46B9dVQExlk/Kq3xPeN1DxF3C+pGgcaALOjUtx3Grtk3dVHGFtFSLFggKCNmU
DAFLKtxp0hXTJj/DAmMDZ47oU3dzNO/nHM/AFeMceVq+qVLu6RTij2Jb0pQ4llnC
bk+aqBPaSG3vvO/zpd3tvw5q9lr+c/uLqH2uyveERHHXX5b3MQOwMUsLCTsJEWYI
9nVr18DiC2WIsEf0cGSOGUJQXZwdApOMi/vc9UNabp4mVGRPnAnYUvBSryFuUtHv
JQ5acgJzAgMBAAECggEBAJEliri2PVLM8eyHfXMMXAHX2BHKLlymp9OLtkqQbFPT
BN65b88mXAeLA7CayxO2hXTkQbs6GgdXK4eMdAanlcFGQLJYZvEI7YowLoMqHjB6
kZWNtKlXJr+mj5bi5qp5ciIvqNn78C4MMl1V3u/GTH1IH+e5e5C8tVhojpVwlbyr
3yQkkQCCn6EEPNQ5SCj1GLZLV4K8azEQ60oMFep/2Kl+k074ecIARtcJKFISFSA9
F2gMl77b3gdLv68L6LZWmhBZiJ2n6HKQ7S9R7xSjr426FGAodOJs5CtTBMVsGmob
CfZHxO9o1sSZOn+uJk/c66riOXNFiA/RSvdo2jKFrKkCgYEA8rhw0CGWJ4gAThmT
iIf2wCI94P6kotHKkMooygDUve/fZjiMEQgNCHYB6hFpYlGC26/H96vSfveUBqlp
Lay/1w+KowjS19pEClwjoogGdUi6CAts+eSw/jgxwRPbtjAaeLcOod8kvv+75Oxp
ga/mWwrsA3LCVDLWUeJrVw545O8CgYEA2P0nP//WCEmLqLi9YO1FVsaHvmwUP2IW
2BAh9FIFgK9JxWTiNmcl6N3XSjEbwvZbco9G5HtOo5iwOZl/mGEE25ksVC0ySL9+
+f7TqcQG9LK/+JqbucR2AfLYqRIGa3VLhXJbT43GePOqdlaFosTl+2MPNg+9bvZ1
W+s9lHxK4r0CgYEArF4ZF2VSqd4mQVBeek38CHQIt5h+uHX9wZcfIl02t2/6mTA9
H/c0sjaDo4Mb8Mtr/7E0dAlcYfhV8ekrHVmZnxOVY7Rnbwy81xKZ59lrpKyyF/Zt
PIWQv+iORMxicl503hc51/CMuusHt0nAn22YTD1UYBqGMJ8tnlcJ3XgUmJcCgYAE
VlsYfmaq172A6+BtNZDzQRiph8OH2NAYFYp4NcOCZP6WgYO8DqfFVdnd08l4RjBh
w9do7cYOoxiyrgzM4POV6CPostaUea9yE9PrSs3QylnoAD8ooXKya0ZFauTR9RBD
ZJvKpUzYUhaQMv6M2F64faxqKjphI3AJHFSoySs+CQKBgDb0b70GyYjff0+DmcSH
muglpBtu/nUAa1ReTLXSdg4dyecCT1SrC6tl5swYvhquBGWlAzFVmZDkkvm8pDls
mAlRIqXN2sMmJsvHxLRIsE3IgjGyXwa1jF0O2vB3ouTvdfAE8xMSuAv/NaRvkgek
AGDiGZwHtggywUGmiqTKzgsH
-----END PRIVATE KEY-----"""

    testcert = """-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIJAJ+nkQeu+is3MA0GCSqGSIb3DQEBCwUAMDgxETAPBgNV
BAgMCGV0aGVyZWFsMQ0wCwYDVQQHDARnYXRlMRQwEgYDVQQDDAtrZXlwYWQudGVz
dDAeFw0xOTA1MTEyMzI1MTFaFw0xOTA2MTAyMzI1MTFaMDgxETAPBgNVBAgMCGV0
aGVyZWFsMQ0wCwYDVQQHDARnYXRlMRQwEgYDVQQDDAtrZXlwYWQudGVzdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM27pK3hLAF/E50UBq4jktQhyM7o
VNwk/NyfnzWG82IcseokkTg3B7kgA7JHUmfHC4TDQqoY6TajHaF9E7joH11VATGW
T8qrfE943UPEXcL6kaBxoAs6NS3Hcau2Td1UcYW0VIsWCAoI2ZQMAUsq3GnSFdMm
P8MCYwNnjuhTd3M07+ccz8AV4xx5Wr6pUu7pFOKPYlvSlDiWWcJuT5qoE9pIbe+8
7/Ol3e2/Dmr2Wv5z+4uofa7K94REcddflvcxA7AxSwsJOwkRZgj2dWvXwOILZYiw
R/RwZI4ZQlBdnB0Ck4yL+9z1Q1puniZUZE+cCdhS8FKvIW5S0e8lDlpyAnMCAwEA
AaNQME4wHQYDVR0OBBYEFGOnrduSgC1B0ave/s2VWsN+uiQ5MB8GA1UdIwQYMBaA
FGOnrduSgC1B0ave/s2VWsN+uiQ5MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAMWErBcuIi5pn17LZ6btRvRLELzLJNxMxWWZ6DbBqvw6tr6vFZLIOVgS
DLth1VK78gNz9yz0ZBBvxh79uNkBFPT6oYL4kYwW3EaLDkCbMwSTWg5Q8o7vO6Z/
Brj9qMRj12Hy1BV0k+q4sBKX+nUGDVMUKeOu73sgUyH48z6NfrbygqkJ8ArTtbKw
tLo9C0zCC4+9RCj3NxKoVKNTj0oQCGNNnR5pxEDZ3lVUb37/2oi0kfLaLpqrcLnz
srrwFBn698+UBKJLXzGiWQx6gCQLAIrxrzLGsI6LH2e4GdyxQPReary1f/yvX1Da
+n5+ZInb63DZeskB01mCHqNC7A6mcIQ=
-----END CERTIFICATE-----"""

    print("Testing Administrative Interface...")

    micropython.alloc_emergency_exception_buf(100)

    config = configuration.Configuration()

    if config.DEBUG:
        import statusled
        led = statusled.StatusLED()
        led.start()
        led.blink_fast(led.GREEN)   # Blinking light to watch blocking

    conn = connection.Connection(config)
    conn.start()

    dashboard = WebAdmin(config, testkey, testcert)
    dashboard.start()

    loop = asyncio.get_event_loop()
    loop.create_task(conn.stay_connected())
    loop.create_task(dashboard.listen_https())
    loop.create_task(dashboard.listen_http())
    if config.DEBUG:
        loop.create_task(led.blink_lights())
    loop.run_forever()

if __name__ == '__main__':
    main()

run = main
