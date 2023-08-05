from flask import Flask, render_template, request, Response, make_response, jsonify
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)

SECRET="redteam rocks!"

# Decorator function to check if the request's host matches the required host
def check_host_decorator(required_host):
    def actual_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.headers["Host"].split(":")[0] == required_host:
                return func(*args, **kwargs)
            else:
                return "ok"
        return wrapper
    return actual_decorator


# Decorator function that validates a cookie value and sets the response header using a callback function
def validate_cookie_decorator(cookie_name, required_value, set_header_callback):
    def actual_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            secret_cookie = request.cookies.get(cookie_name, "")

            if secret_cookie == required_value:
                response = func(*args, **kwargs)
            else:
                response = Response("Unauthorized", status=401)

            set_header_callback(response)
            return response

        return wrapper
    return actual_decorator


# Callback function to set the Access-Control-Allow-Origin header to *
def set_acao_header_star(response):
    response.headers["Access-Control-Allow-Origin"] = "*"

# Callback function to set the Access-Control-Allow-Origin header based on the request Origin
def set_acao_header_origin(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get(
        "Origin", "http://cors-lab.com:8000/"
    )
    """
    a better approach
    whitelist = ['asdf.com','cors-lab.com']
    for i in whitelist:
        if request.headers.get("Origin", "http://cors-lab.com:8000/") == i:
            response.headers["Access-Control-Allow-Origin"] = i
            break
    """

# Callback function to set the Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers based on the request Origin
def set_acao_acac_headers_origin(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get(
        "Origin", "http://cors-lab.com:8000/"
    )
    response.headers["Access-Control-Allow-Credentials"] = "true"

@app.route("/")
@check_host_decorator("cors-lab.com")
def hello():
    return render_template("index.html")

# exploit the SameSite=None and Secure=True
@app.route("/exploit.html")
@check_host_decorator("cors-exp.com")
def exploit():
    return render_template("exploit.html")

# exploit the subdomain takeover or XSS on subdomains
@app.route("/sub-exploit.html")
@check_host_decorator("sub.cors-lab.com")
def sub():
    return render_template("exploit.html")

# weird behaviour for firefox
@app.route("/iframe.html")
@check_host_decorator("cors-lab.com")
def iframe():
    return render_template("iframe.html")


# public api, no need auth
@app.route("/notime")
@check_host_decorator("api.cors-lab.com")
def notime():
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%H:%M:%S")
    response = Response(current_time)
    return response

@app.route("/local-secret")
@check_host_decorator("127.0.0.1")
def local_secret():
    response = Response("this is a top secret!!!")
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

# public api, no need auth
@app.route("/time")
@check_host_decorator("api.cors-lab.com")
def time():
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%H:%M:%S")
    response = Response(current_time)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.route("/cookie-auth")
@check_host_decorator("api.cors-lab.com")
def cookie_auth():
    response = make_response("Cookie has been set.")

    # set the secret cookie
    response.set_cookie("secret", "asdf1234")

    # Set the Access-Control-Allow-Origin headers and Access-Control-Allow-Credentials to the specific origin
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/cookie-auth-2")
@check_host_decorator("api.cors-lab.com")
def cookie_auth_2():
    response = make_response("Cookie has been set.")

    # set the secret cookie
    response.set_cookie("secret", "asdf1234", samesite="None", secure=True)

    # Set the Access-Control-Allow-Origin headers and Access-Control-Allow-Credentials to the specific origin
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/token-auth")
@check_host_decorator("api.cors-lab.com")
def token_auth():
    response = make_response("Custom header has been set.")

    # Set the x-auth-token header
    response.headers["x-auth-token"] = "asdf1234"

    # Set the Access-Control-Allow-Origin headers and Access-Control-Expose-Headers to the specific origin
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Expose-Headers"] = "x-auth-token"
    return response


# won't work. `Access-Control-Allow-Origin: *` does not work for cookie-authenticated requests
@app.route("/cookie-secret-1")
@check_host_decorator("api.cors-lab.com")
@validate_cookie_decorator('secret','asdf1234',set_acao_header_star)
def cookie_secret_1():
    response = Response(SECRET)
    return response


# won't work. cookie-authenticated requests must have `Access-Control-Allow-Credentials` set to `true`
@app.route("/cookie-secret-2")
@check_host_decorator("api.cors-lab.com")
@validate_cookie_decorator('secret','asdf1234',set_acao_header_origin)
def cookie_secret_2():
    response = Response(SECRET)
    return response


@app.route("/cookie-secret-3")
@check_host_decorator("api.cors-lab.com")
@validate_cookie_decorator('secret','asdf1234',set_acao_acac_headers_origin)
def cookie_secret_3():
    response = Response(SECRET)
    return response


@app.route("/edit-secret", methods=["OPTIONS"])
@check_host_decorator("api.cors-lab.com")
def edit_secret_preflight():
    origin = request.headers.get('Origin', "https://cors-lab.com:8000/")
    headers = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': "true",
        'Access-Control-Allow-Methods': 'GET, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'content-type'
    }
    return Response('', status=204, headers=headers)

@app.route("/edit-secret", methods=["PATCH"])
@check_host_decorator("api.cors-lab.com")
@validate_cookie_decorator('secret','asdf1234',set_acao_acac_headers_origin)
def edit_secret():
    print('asdfasdfasdfasdfasdf')
    global SECRET
    data = request.json
    SECRET = data.get('secret', SECRET)
    print(SECRET)
    return Response("Secret has been updated to: "+SECRET)


@app.route("/token-secret-1", methods=['GET'])
@check_host_decorator("api.cors-lab.com")
def token_secret_1():
    secret_token = request.headers.get("x-auth-token", "")

    if secret_token == "asdf1234":
        response = Response(SECRET)
    else:
        response = Response("Unauthorized", status=401)

    response.headers["Access-Control-Allow-Origin"] = request.headers.get(
        "Origin", "http://cors-lab.com:8000/"
    )
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route('/token-secret-2', methods=['OPTIONS'])
@check_host_decorator("api.cors-lab.com")
def token_secret_2_preflight():
    origin = request.headers.get('Origin', "https://cors-lab.com:8000/")
    headers = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'x-auth-token'
    }

    return Response('', status=204, headers=headers)


@app.route("/token-secret-2", methods=['GET'])
@check_host_decorator("api.cors-lab.com")
def token_secret_2():
    secret_token = request.headers.get("x-auth-token", "")

    if secret_token == "asdf1234":
        response = Response(SECRET)
    else:
        response = Response("Unauthorized", status=401)

    response.headers["Access-Control-Allow-Origin"] = request.headers.get(
        "Origin", "http://cors-lab.com:8000/"
    )
    test = 1
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True, ssl_context='adhoc')
