from flask import Flask, render_template, url_for, request, flash, redirect
from sqlinjection import scan_sql_injection
from urllib.parse import unquote 
from apiendpoint import analyze_endpoints
from openredirect import is_open_redirect
from crosssitescriptting import crosssitescripting_result
from securityheaders import check_http_security_headers
from securitymisconfig import check_security_misconfiguration
from tls import check_tls_security
app = Flask(__name__)

@app.route('/')

def index():
    return render_template('frontpage.html')

@app.route('/loginpage')

def loginpage():
    return render_template('loginpage.html')


@app.route('/signuppage')

def signup():
    return render_template('signuppage.html')

@app.route('/sqlinjection')
def sql():
 return render_template('sqlinjection.html')

@app.route('/getinputsql', methods=['POST'])
def getinput():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            user_input = unquote(user_input.replace('%22', ''))
            resultforms = scan_sql_injection(user_input)
            
            return render_template('sqlinjection.html', result1=resultforms) 
        else:
            return "NO INPUT RECEIVED", 404


@app.route('/apiendipoint')
def apiendipoint():
    return render_template('apiendpoint.html')

@app.route('/getinputapi', methods=['POST'])
def getinputapi():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            user_input = unquote(user_input.replace('%22', ''))
            apiresult = analyze_endpoints(user_input)
            return render_template('apiendpoint.html', resultapi=apiresult)
        else:
            return "No Input Provides.", 404


@app.route('/openredirect')
def openredirect():
    return render_template('openredirect.html')

@app.route('/getinputopenredirect', methods=['POST'])
def getinputopenredirect():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            openredirectresult = is_open_redirect(user_input)
            return render_template('openredirect.html', resultopenredirect=openredirectresult)
        else:
            return "No Input Provides.", 404

@app.route('/crosssitescripting')
def crosssitescripting():
    return render_template('crosssitescriptting.html')

@app.route('/getinputcrosssitescriptting', methods=['POST'])
def getinputcrosssitescriptting():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            crosssites_result = crosssitescripting_result(user_input)
            return render_template('crosssitescriptting.html', result_crosssite=crosssites_result)
        else:
            return "No Input Provides.", 404


@app.route('/securityheaders')
def securityheaders():
 return render_template('securityheaders.html')

@app.route('/getinput_SecurityHeaders', methods = ['POST'])
def getinput_SecurityHeaders():
     if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            headers_results = check_http_security_headers(user_input)
            return render_template('securityheaders.html', result_headers = headers_results)
        else:
            return "No Input Provides.", 404

@app.route('/securitymisconfig')
def securitymisconfig():
    return render_template('securitymisconfig.html')

@app.route('/securitymisconfiginput', methods = ['POST'])
def securitymisconfiginput():
    if request.method == 'POST':
     user_input = request.form.get('url')
     if(user_input):
         securitymisconfig_result = check_security_misconfiguration(user_input)
         return render_template('securitymisconfig.html', result_securitymisconfig=securitymisconfig_result)
     else:
         return ' No Input Found', 404
     
    
@app.route('/tls')
def tls():
  return render_template('tls.html')

@app.route('/tlsinput',  methods = ['POST'])
def tlsinput():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            tls_result = check_tls_security(user_input)
            return render_template('tls.html', result_tls = tls_result )
    else:
         return ' No Input Found', 404

if __name__ == "__main__":
     app.run(debug=True)
