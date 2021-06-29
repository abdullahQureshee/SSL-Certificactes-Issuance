from itertools import chain
from flask import Flask, render_template, url_for, request, redirect, send_file
from blockchain import Blockchain
from transaction import Transaction
from zipfile38 import ZipFile
from filehandler import FileHandler


blockchain = Blockchain()
filer = FileHandler()
loggedin = None
app = Flask(__name__)
csr_cache = {}
user_returned_tokens = {}
ROOTCA = blockchain.createMiner()


@app.route("/getcert")
def getcert():
    return render_template("getcert.html")


@app.route("/getcert1", methods=["POST"])
def getcert1():
    name = request.form.get('name')
    if name is not None:
        for block in reversed(blockchain.chain):
            if block.crt == 'revoke':
                break
            if name == block.domain:
                if filer.file_exists(
                    filer.path_join(
                        app.root_path, "certificates", name + ".crt")
                ):
                    return send_file(
                        filer.path_join(
                            app.root_path, "certificates", name + ".crt"
                        ),
                        as_attachment=True)
    return render_template("errusr.html", header="No Certificate Available",
                           content="Please make sure that you have a ceritificate issued to "+name)


@app.route("/gen_token1", methods=["POST"])
def gen_token1():
    form = request.form
    domain = form.get('domain')
    token = form.get('token')
    if token is not None and domain is not None:
        filer.write(
            filer.path_join(app.root_path, 'tokens',
                            domain+'.TOKEN', "", token)
        )
    return redirect('/miner')


@app.route("/revoke")
def revoke():
    return render_template("register.html", status='revoke')


@app.route("/gen_token/<tx>/<status>")
def gen_token(tx, status):
    if status == 'initial' and filer.file_exists(
            filer.path_join(app.root_path, "tokens", tx + ".TOKEN")
    ):
        return redirect("/miner")
    tx = blockchain.utp.get(tx)
    if tx is not None:
        result = ROOTCA.domain_check(tx.domain, tx.pk)
        if status == 'revoke':
            result = not result
        if result:
            # if ROOTCA.key_check(tx.pk,tx.sig):
            pass
            # else:
            #    return render_template('errusr.html',
            #    header="key binding couldn't be verified",
            #    content=" ")
        else:
            return render_template('errusr.html',
                                   header="domain already exists" if status == 'initial' else "domain doesn't exist",
                                   content=" ")
        token = ROOTCA.token_placement(tx)
        filer.write(
            filer.path_join(app.root_path, "tokens", tx.domain + ".TOKEN"),
            'b', token
        )
    return redirect("/miner")


@app.route("/validate")
def validate():
    return render_template("validate.html")


@app.route("/validate2/<domain>")
def validate2(domain):
    p = filer.path_join(app.root_path, "usrplacedtokens", domain+".TOKEN")
    if filer.file_exists(p):
        csr = csr_cache.get(domain)
        usrtoken = filer.read(p, 'b')
        token = filer.read(
            filer.path_join(app.root_path,
                            "tokens", domain+".TOKEN"
                            ), 'b')
        cert = ROOTCA.create_cert_for(csr)
        if blockchain.verify(cert, usrtoken, token):
            pass
        else:
            return redirect("/miner")

        csr_cache.pop(domain)
        if ROOTCA.mine(blockchain.utp.get(domain), cert.get_notAfter()):
            filer.write(
                filer.path_join(app.root_path, "certificates",
                                domain + ".crt"), 'b',
                blockchain.dump(cert, 'cert')
            )
    return redirect("/miner")


@app.route("/miner")
def miner():
    return render_template("miner.html", utp=blockchain.utp,
                           usrToken=csr_cache, mytokens=ROOTCA.mytokens)


@app.route("/gettoken")
def gettoken():
    return render_template("gettoken.html")


@app.route("/gettoken1", methods=['POST'])
def gettoken1():
    domain = request.form['domain']
    if filer.file_exists(
        filer.path_join(
            app.root_path, "tokens", domain + ".TOKEN"
        )
    ):
        return send_file(filer.path_join(app.root_path, "tokens", domain + ".TOKEN"), as_attachment=True)
    return render_template("errusr.html", header="Doesn't Exists!",
                           content="Token doesn't exist.")


@app.route("/placetoken", methods=["POST"])
def placetoken():
    name = request.form['name']
    filer.write(
        filer.path_join(
            app.root_path, "usrplacedtokens",
            name + ".TOKEN"
        ),
        'b',
        request.files['token'].read()
    )
    return redirect("/domain/"+name)


@app.route("/signtoken", methods=["POST"])
def signtoken():
    key = request.files['key'].read()
    token = request.files['token'].read()
    name = request.form['name']
    name = filer.path_join(
        app.root_path,
        "tokens",
        "signed_"+name+".TOKEN"
    )
    key = blockchain.load(key, 'sk')
    cert = blockchain.create_certificate(key)
    filer.write(
        name,
        'b',
        blockchain.sign(key, token))
    return send_file(
        filer.path_join(app.root_path, "tokens", name),
        as_attachment=True
    )


@app.route("/gencsr")
def gencsr():
    return render_template("register.html", csr='initial')


@app.route("/domain/<name>")
def domain(name):
    return render_template('domain.html', name=name)


@app.route("/viewrevoked1", methods=["POST"])
def viewrevoked1():
    pk = request.files['pk'].read()
    pk = blockchain.b16encode(pk)
    domains = []
    for block in blockchain.chain:
        if block.crt == 'revoke':
            if pk == block.pk:
                domains.append(block.domain)
    return render_template("errusr.html",
                           header='Following domains are registered with the provided Public Key.',
                           content=', '.join(domains))


@app.route("/viewrevoked")
def viewrevoked():
    return render_template("viewrevoked.html")


@app.route("/certificates1", methods=["POST"])
def certificates1():
    pk = request.files['pk'].read()
    pk = blockchain.b16encode(pk)
    domains = []
    for block in blockchain.chain:
        if block.domain in domains and block.crt == 'revoke':
            domains.remove(block.domain)
            continue
        if block.pk == pk:
            domains.append(block.domain)
    return render_template("errusr.html",
                           header='Following domains are registered with the provided Public Key.',
                           content=', '.join(domains))


@app.route("/certificates")
def certificates():
    return render_template("viewcerts.html")


@app.route("/pendingreqs1", methods=['POST'])
def pendingreqs1():
    pk = request.files['pk'].read()
    pk = blockchain.b16encode(pk)
    domains = []
    for domain, data in csr_cache.items():
        if pk == blockchain.b16encode(
            blockchain.dump(data.get_pubkey(), 'sk')
        ):
            domains.append(domain)
    return render_template("errusr.html",
                           header='Following domains are pending.',
                           content=', '.join(domains))


@app.route("/pendingreqs")
def pendingreqs():
    return render_template("pendreq.html")


@app.route("/createcsr/<status>", methods=['POST', 'GET'])
def createcsr(status):
    form = request.form
    _path = filer.path_join(app.root_path, "csr/")
    nodename = form['nodename']
    if status == 'initial':
        req = blockchain.create_csr(
            CN=nodename,
            ST=form['state'],
            L=form['location'],
            O=form['organization'],
            OU=form['orgunit'],
            emailAddress=form['email']
        )
    else:
        for block in reversed(blockchain.chain):
            if nodename == block.domain:
                if block.crt == 'revoke':
                    return render_template("errusr.html",
                                           header="domain error",
                                           content="No domain exists to be able to be revoked.")
                else:
                    break
        p = filer.path_join(app.root_path, "certificates", nodename+".crt")
        if filer.file_exists(p):
            d = filer.read(p, 'b')
            req = blockchain.load(
                d, 'cert'
            ).get_subject().get_components()
            for i in range(len(req)):
                req[i] = (bytes.decode(req[i][0]), bytes.decode(req[i][1]))
            req = dict(req)
            key = blockchain.load(
                filer.read(
                    filer.path_join(
                        app.root_path, "keys", nodename + "_s.key"
                    ),
                    'b'),
                'sk'
            )
            req = blockchain.create_csr(key=key, **req)

    filer.write(_path+nodename+".csr", 'b', blockchain.dump(req, 'csr'))
    filer.write(
        filer.path_join(app.root_path, "keys", nodename + "_s.key"),
        'b',
        blockchain.dump(req.get_pubkey(), 'sk')
    )
    filer.write(
        filer.path_join(app.root_path, "keys", nodename + "_p.key"),
        'b',
        blockchain.dump(req.get_pubkey(), 'pk')
    )
    z = ZipFile(filer.path_join(app.root_path, "zips", nodename+".zip"), 'w')
    z.write(filer.path_join(app.root_path, "csr",
            nodename+".csr"), nodename+".csr")
    z.write(filer.path_join(app.root_path, "keys",
            nodename+"_p.key"), nodename+"_p.key")
    z.write(filer.path_join(app.root_path, "keys",
            nodename+"_s.key"), nodename+"_s.key")
    # creating transaction
    s = req.get_subject()
    csr_cache.setdefault(s.CN, req)
    blockchain.utp.setdefault(s.CN,
                              blockchain.createTrans(
                                  {
                                      'domain': s.CN,
                                      'pk': req.get_pubkey(),
                                      'sig': blockchain.extract_signature(blockchain.dump(req, 'csr'), 'csr', 'bytes'),
                                      'crt': status
                                  }
                              )
                              )
    return send_file(filer.path_join(app.root_path, "zips", nodename+".zip"), as_attachment=True,
                     mimetype="zip")


@app.route("/signout")
def signout():
    global loggedin
    loggedin = None
    return redirect("/")


@app.route("/login1", methods=['POST'])
def login1():
    form = request.form
    name = form.get('name')
    pw = form.get('password')
    data = blockchain.users.get(name)
    if data:
        stored_pw = data['pw']
        if hash(pw) == stored_pw:
            global loggedin
            loggedin = data['entity']
            return redirect("/user/" + name)
        else:
            return render_template("errusr.html",
                                   header="Invalid Password",
                                   content="Password doen't match. Forgot Password? Haha")
    else:
        return redirect("/errusr/ghost")


@app.route("/signin1", methods=['POST'])
def sigin1():
    form = request.form
    name = form.get('name')
    pw = form.get('password')
    if blockchain.users.get(name):
        return redirect("/errusr/reg")
    u = blockchain.create_user(name)
    blockchain.users.setdefault(name, {
        'pw': hash(pw),
        'entity': u
    })
    global loggedin
    loggedin = u
    return redirect("/user/"+name)


@app.route("/errusr/<status>")
def errusr(status):
    if status == "ghost":
        return render_template("errusr.html",
                               header="No Such User Exists",
                               content="Please Signin or make sure entered credentials are correct.", loggedin=loggedin)
    return render_template("errusr.html",
                           header="User Exists",
                           content="A user with this name already exists. If that user is "
                           "you, please navigate to Login.", loggedin=loggedin)


@app.route("/signin")
def signin():
    return render_template('signin.html')


@app.route("/")
def index():
    return render_template("index.html", chain=blockchain.chain, loggedin=loggedin)


@app.route("/contributors")
def contributors():
    return render_template('contributors.html', loggedin=loggedin)


@app.route("/user/<name>")
def user(name):
    return render_template("user.html", name=name, usr=loggedin, loggedin=loggedin)


@app.route("/about")
def about():
    return render_template("about.html", loggedin=loggedin)


@app.route("/login", methods=['GET', 'POST'])
def login():
    return render_template("login.html")


@app.route("/user/<name>/<csr>/register")
def register(name, csr):
    return render_template("register.html", name=name, csr=csr, loggedin=loggedin)


@app.route("/search")
def search():
    return render_template('search.html')


@app.route("/search1", methods=['GET', 'POST'])
def search1():
    form = request.form
    choice = form.get('by')
    return render_template('searchby.html', choice=choice)


@app.route("/search2", methods=['GET', 'POST'])
def search2():
    form = request.form
    value = form.get('value')
    if value.isnumeric():
        value = int(value)
        print(value)
        if 0 < value <= len(blockchain.chain):
            return render_template('errusr.html', header='', content=str(blockchain.chain[value-1]))
    elif (value.isalnum()):
        for block in blockchain.chain:
            if block.hash == value:
                return render_template('errusr.html', header='', content=str(block))
    return render_template('errusr.html', header='No block found', content='')


@app.route('/feedback')
def feedback():
    return render_template('feedback.html')


@app.route('/feedback1', methods=['GET', 'POST'])
def feedback1():
    form = request.form
    email = form.get('email')
    feedback = form.get('feedback')
    return render_template('errusr.html', header='Feedback Submitted', content='')


if __name__ == "__main__":
    app.run()
