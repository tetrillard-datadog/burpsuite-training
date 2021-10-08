from flask import Flask, request, session
import zlib
from base64 import b64encode
from functools import wraps
from Crypto.Hash import HMAC, SHA256
import ipaddress
import inspect
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not (auth and auth.username == "admin" and auth.password == "123456"):
            return (
                "Unauthorized",
                401,
                {"WWW-Authenticate": 'Basic realm="login: admin passwd: ??"'},
            )
        return f(*args, **kwargs)

    return decorated_function


def wrap_response(fn=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            content = f(*args, **kwargs)
            if isinstance(content, tuple):
                return content
            else:
                return fn(content)

        return decorated_function

    return decorator


def lfi(request):
    requested_file = request.args.get("filename", "")
    if requested_file == "":
        return b"filename GET parameter is missing."
    with open(requested_file, "rb") as f:
        content = f.read()
        return content


@app.route("/")
def index():
    content = "<ul>\n"
    for rule in app.url_map.iter_rules():
        if rule.endpoint.startswith("level"):
            description = inspect.getdoc(globals()[rule.endpoint])
            path = rule.rule
            content += f'<li><a href="{path}">{path[1:]}</a> : {description}</li> \n'
    content += "</ul>\n"
    return content


@app.route("/level0")
@login_required
def level0():
    """
    Fun with basic Authorization
    """
    return "Well done! flag{level0}"


@app.route("/level1")
@wrap_response(b64encode)
def level1():
    """
    Decode the answer 1st edition.
    """
    try:
        return lfi(request)
    except:
        return "Unspecified error, aborting...", 500


@app.route("/level2")
@wrap_response(b64encode)
@wrap_response(zlib.compress)
def level2():
    """
    Decode the answer, 2nd edition - You should have the code by now, so you know what to do
    """
    try:
        return lfi(request)
    except:
        return b"Unspecified error, aborting...", 500


@app.route("/level4")
def level4():
    """
    Fun with random stuff
    """
    LEVEL4_LIMIT = 10
    current_ip = request.headers.get("X-Real-IP", request.remote_addr)
    try:
        ipaddress.ip_address(current_ip)
    except:
        return "Provided X-Real-IP does not seem like a real IP, abort!", 400
    if "last_ip" not in session:
        session["last_ip"] = current_ip
        session["counter"] = 0
        return f"Session started ! Come back again with {LEVEL4_LIMIT} different X-Real-IP headers"
    else:
        if session["last_ip"] != current_ip:
            session["counter"] += 1
        else:
            session["counter"] = 0
        if session["counter"] >= LEVEL4_LIMIT:
            return "Well done! Here, take this 🍰."

    return f"X-Real-Ip: {current_ip}, counter: {session['counter']} < {LEVEL4_LIMIT}"


@app.route("/level5")
def level5():
    """
    Fun with random stuff and variables
    """
    LEVEL4_LIMIT = 10
    current_ip = request.headers.get("X-Real-IP", request.remote_addr)
    try:
        ipaddress.ip_address(current_ip)
    except:
        return "Provided X-Real-IP does not seem like a real IP, abort!", 400
    if "ip_list" not in session:
        session["ip_list"] = []
        session["ip_list"].append(current_ip)
        session["counter"] = 0
        return f"Session started ! Come back again with {LEVEL4_LIMIT} different X-Real-IP, and GET parameter `ip_address` == X-Real-IP"
    else:
        if current_ip != request.args.get("ip_address", ""):
            return (
                "Provided X-Real-IP does not match the `ip_address` GET parameter",
                400,
            )
        if current_ip not in session["ip_list"]:
            session["counter"] += 1
        else:
            session["counter"] = 0
        if session["counter"] >= LEVEL4_LIMIT:
            return "Well done! Have a 🍰."

    return f"X-Real-Ip: {current_ip}, counter: {session['counter']} < {LEVEL4_LIMIT}"


@app.route("/level6", methods=["GET", "POST"])
def level6():
    """
    You'll figure out with the source code
    """
    secret = bytes(request.headers.get("Secret", ""), "utf-8")
    if secret == b"":
        return "Secret header is empty/missing."

    mac = request.args.get("mac", "")
    data = request.get_data()
    ts = int(data)
    cur_ts = int(datetime.now().timestamp())
    diff = ts - cur_ts
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(data)
    if h.hexdigest() == mac and ts - cur_ts == 0:
        return "Well done! Take this 🍰."
    else:
        return f"Calculated: {h.hexdigest()}, timestamps diff: {diff}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
