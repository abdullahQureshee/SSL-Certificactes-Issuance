from flask import Flask, render_template, url_for, request, redirect, send_file
from proofchain import Proofchain
from random import randint
from OpenSSL import crypto
from os import path
from transaction import Transaction
from zipfile38 import ZipFile


proofchain = Proofchain()
loggedin = None
app = Flask(__name__)
csr_cache = {}
user_returned_tokens = {}
ROOTCA = proofchain.createMiner()
proofchain.gen_csr

@app.route("/getcert")
def getcert():
    return render_template("getcert.html")

@app.route("/getcert1", methods=["POST"])
def getcert1():
    name = request.form.get('name')
    if name is not None:
        if proofchain.file_exists(
            proofchain.path_join(app.root_path, "certificates", name + ".crt")
        ):
            return send_file(
                proofchain.path_join(
                        app.root_path, "certificates", name + ".crt"
                    ),
                as_attachment=True)
    return render_template("errusr.html",header="No Certificate Available",
    content="Please make sure that you have a ceritificate issued to "+name)

@app.route("/gen_token1",methods=["POST"])
def gen_token1():
    form = request.form
    domain = form.get('domain')
    token = form.get('token')
    if token is not None and domain is not None:
        proofchain.write(
            proofchain.path_join(app.root_path,'tokens',domain+'.TOKEN',"",token)
        )
    return redirect('/miner')


@app.route("/revoke")
def revoke():
    return render_template("register.html",status='revoke')

@app.route("/gen_token/<tx>/<status>")
def gen_token(tx,status):
    if status == 'initial' and proofchain.file_exists(
            proofchain.path_join(app.root_path, "tokens", tx + ".TOKEN")
    ):
        return redirect("/miner")
    tx = proofchain.utp.get(tx)
    if tx is not None:
        result = ROOTCA.domain_check(tx.domain,tx.pk)
        if status == 'revoke':
            result = not result
        if result:
            #if ROOTCA.key_check(tx.pk,tx.sig):
            pass
            #else:
            #    return render_template('errusr.html',
            #    header="key binding couldn't be verified",
            #    content=" ")
        else:
            return render_template('errusr.html',
            header="domain already exists" if status == 'initial' else "domain doesn't exist",
            content = " ")
        token = ROOTCA.token_placement(tx)
        proofchain.write(
            proofchain.path_join(app.root_path, "tokens", tx.domain + ".TOKEN"),
            'b', token
        )
    return redirect("/miner")

@app.route("/validate")
def validate():
    return render_template("validate.html")

@app.route("/validate2/<domain>")
def validate2(domain):
    p = proofchain.path_join(app.root_path,"usrplacedtokens",domain+".TOKEN")
    if proofchain.file_exists(p):
        csr = csr_cache.get(domain)
        usrtoken = proofchain.read(p,'b')
        #token = open(proofchain.path_join(app.root_path,'tokens',domain+".TOKEN"),
        #'rb').read()#ROOTCA.mytokens.get(domain)
        token = proofchain.read(
            proofchain.path_join(app.root_path,
                "tokens",domain+".TOKEN"
        ),'b')
        cert = ROOTCA.create_cert_for(csr)
        #try:
        #    crypto.verify(cert,
        #        usrtoken,
        #        token,
        #        'sha256')
        #except:
        #    return redirect("/miner")
        if proofchain.verify(cert, usrtoken, token):
            pass
        else:
            return redirect("/miner")
        #open(proofchain.path_join(app.root_path,'certificates',domain+".crt"),
        #'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM,cert))
        
        csr_cache.pop(domain)
        if ROOTCA.mine(proofchain.utp.get(domain),cert.get_notAfter()):
            proofchain.write(
                proofchain.path_join(app.root_path, "certificates",
                domain + ".crt"), 'b',
                proofchain.dump(cert,'cert')
            )
    return redirect("/miner")

@app.route("/miner")
def miner():
    return render_template("miner.html",utp=proofchain.utp,
    usrToken = csr_cache,mytokens = ROOTCA.mytokens)

@app.route("/gettoken")
def gettoken():
    return render_template("gettoken.html")

@app.route("/gettoken1",methods=['POST'])
def gettoken1():
    domain = request.form['domain']
    if proofchain.file_exists(
        proofchain.path_join(
            app.root_path, "tokens", domain + ".TOKEN"
        )
    ):
        return send_file(proofchain.path_join(app.root_path, "tokens", domain + ".TOKEN")
            , as_attachment=True)
    return render_template("errusr.html", header="Doesn't Exists!",
        content = "Token doesn't exist.")

@app.route("/placetoken",methods=["POST"])
def placetoken():
    name = request.form['name']
    proofchain.write(
        proofchain.path_join(
            app.root_path, "usrplacedtokens",
            name + ".TOKEN"
        ),
        'b',
        request.files['token'].read()
    )
    #open(proofchain.path_join(app.root_path,"usrplacedtokens",request.form['name']+".TOKEN"),
    #'wb').write(request.files['token'].read())
    return redirect("/domain/"+name)

@app.route("/signtoken", methods=["POST"])
def signtoken():
    key = request.files['key'].read()
    token = request.files['token'].read()
    name = request.form['name']
    name = proofchain.path_join(
        app.root_path,
        "tokens",
        "signed_"+name+".TOKEN"
    )
    key = proofchain.load_privatekey(key)
    cert = proofchain.create_certificate(key)
    #f = open(proofchain.path_join(app.root_path,"tokens","signed_"+name+".TOKEN"),'wb')
    #f.write(proofchain.sign(key,token,'sha256'))
    #f.flush()
    #f.close()
    proofchain.write(
        name,
        'b',
        proofchain.sign(key,token))
    return send_file(
        proofchain.path_join(app.root_path,"tokens",name),
        as_attachment=True
    )

@app.route("/gencsr")
def gencsr():
    return render_template("register.html",status='initial')

@app.route("/domain/<name>")
def domain(name):
    return render_template('domain.html', name=name)

@app.route("/viewrevoked1", methods=["POST"])
def viewrevoked1():
    pk = request.files['pk'].read()
    domains = []
    for block in proofchain.chain:
        print(block)
        if block.crt == 'revoke':
            if pk == block.pk:
                domains.append(block.domain)
    return render_template("errusr.html",
    header='Following domains are registered with the provided Public Key.',
    content = ', '.join(domains))

@app.route("/viewrevoked")
def viewrevoked():
    return render_template("viewrevoked.html")

@app.route("/certificates1", methods=["POST"])
def certificates1():
    pk = request.files['pk'].read()
    domains = []
    for block in proofchain.chain:
        print(block)
        if block.domain in domains and block.crt == 'revoke':
            domains.remove(block.domain)
            continue
        if block.pk == pk:
            domains.append(block.domain)
    return render_template("errusr.html",
    header='Following domains are registered with the provided Public Key.',
    content = ', '.join(domains))

@app.route("/certificates")
def certificates():
    return render_template("viewcerts.html")

@app.route("/pendingreqs1",methods=['POST'])
def pendingreqs1():
    pk = request.files['pk'].read()
    domains = []
    for domain, data in csr_cache.items():
        if pk == crypto.b16encode(crypto.dump_publickey(crypto.FILETYPE_PEM,data.get_pubkey())):
            domains.append(domain)
    return render_template("errusr.html",
    header='Following domains are pending.',
    content = ', '.join(domains))

@app.route("/pendingreqs")
def pendingreqs():
    return render_template("pendreq.html")



@app.route("/createcsr/<status>", methods=['POST','GET'])
def createcsr(status):
    form = request.form
    _path = proofchain.path_join(app.root_path,"csr/")
    nodename = form['nodename']
    if status=='initial':
        req = proofchain.gen_csr(
            CN=nodename,
            ST = form['state'],
            L = form['location'],
            O = form['organization'],
            OU = form['orgunit'],
            emailAddress = form['email']
        )
    else:
        for block in reversed(proofchain.chain):
            if nodename == block.domain:
                if block.crt == 'revoke':
                    return render_template("errusr.html",
                    header="domain error",
                    content = "No domain exists to be able to be revoked.")
                else:
                    break
        p = proofchain.path_join(app.root_path,"certificates",nodename+".crt")
        if path.exists(p):
            req = crypto.load_certificate(crypto.FILETYPE_PEM,
            open(p,'rb').read()).get_subject().get_components()
            for i in range(len(req)):
                req[i] = (str(req[i][0]),str(req[i][1]))
                req[i] = (req[i][0][2:len(req[i][0])-1],req[i][1][2:len(req[i][1])-1])
            req = dict(req)
            key = crypto.load_privatekey(crypto.FILETYPE_PEM,
            open(proofchain.path_join(app.root_path,"keys",nodename+"_s.key"),'rb').read())
            req = proofchain.gen_csr(key = key, **req)

    csr = open(_path+nodename+".csr",'wb')
    csr.write(
        crypto.dump_certificate_request(crypto.FILETYPE_PEM,req)
    )
    csr.flush()
    csr.close()
    key = open(proofchain.path_join(app.root_path,"keys",nodename+"_s.key"),'wb')
    key.write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM,req.get_pubkey())
    )
    key.flush()
    key.close()
    open(proofchain.path_join(app.root_path,"keys",nodename+"_p.key"),
    'wb').write((crypto.b16encode(
        crypto.dump_publickey(crypto.FILETYPE_PEM,req.get_pubkey())
    )))
    z = ZipFile(proofchain.path_join(app.root_path,"zips",nodename+".zip"),'w')
    z.write(proofchain.path_join(app.root_path,"csr",nodename+".csr"),nodename+".csr")
    z.write(proofchain.path_join(app.root_path,"keys",nodename+"_p.key"),nodename+"_p.key")
    z.write(proofchain.path_join(app.root_path,"keys",nodename+"_s.key"),nodename+"_s.key")
    #creating transaction
    s = req.get_subject()
    csr_cache.setdefault(s.CN, req)
    proofchain.utp.setdefault(s.CN,
        Transaction(
            s.CN,
            req.get_pubkey(),
            crypto.b16encode(
                crypto.dump_certificate_request(crypto.FILETYPE_PEM,req)
            )[-289:-33],
            status
        )
    )
    return send_file(proofchain.path_join(app.root_path,"zips",nodename+".zip")
        ,as_attachment=True,
        mimetype="zip")

@app.route("/signout")
def signout():
    global loggedin
    loggedin = None
    return redirect("/")

@app.route("/login1",methods = ['POST'])
def login1():
    data = users.get(request.form['name'])
    if data:
        pw = data['pw']
        if hash(request.form['password']) == pw:
            global loggedin
            loggedin = data['entity']
            return redirect("/user/" + request.form['name'])
        else:
            return render_template("errusr.html",
                header="Invalid Password",
                content="Password doen't match. Forgot Password? Haha")
    else:
        return redirect("/errusr/ghost")


@app.route("/signin1",methods = ['POST'])
def sigin1():
    name = request.form['name']
    pw = request.form['password']
    if users.get(name):
        return redirect("/errusr/reg")
    u = proofchain.createUser(name,"")
    users.setdefault(name, {
        'pw': hash(pw),
        'entity': u
    })
    global loggedin
    loggedin = u
    return redirect("/user/"+request.form['name'])

@app.route("/errusr/<status>")
def errusr(status):
    if status == "ghost":
        return render_template("errusr.html",
        header="No Such User Exists",
        content="Please Signin or make sure entered credentials are correct."
        , loggedin = loggedin)
    return render_template("errusr.html",
    header="User Exists",
    content = "A user with this name already exists. If that user is "
            "you, please navigate to Login.", loggedin = loggedin)

@app.route("/signin")
def signin():
    return render_template('signin.html', loggedin = loggedin)

@app.route("/")
def index():
    return render_template("index.html",chain = proofchain.chain, loggedin=loggedin)

@app.route("/contributors")
def contributors():
    return render_template('contributors.html', loggedin = loggedin)

@app.route("/user/<name>")
def user(name):
    return render_template("user.html",name = name,usr = loggedin, loggedin = loggedin)

@app.route("/about")
def about():
    return render_template("about.html", loggedin = loggedin)

@app.route("/login",methods=['GET','POST'])
def login():
    return render_template("login.html", loggedin = loggedin)

@app.route("/user/<name>/<csr>/register")
def register(name,csr):
    return render_template("register.html",name = name, csr=csr, loggedin = loggedin)

app.run()