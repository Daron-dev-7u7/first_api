from flask import Flask, render_template, url_for,redirect,session,request,flash
from pymongo import MongoClient
#para cargar los archivos .env
from dotenv  import load_dotenv
import os
# algorito de encriptacion
from passlib.hash import pbkdf2_sha256
from bson import ObjectId


#esta funcion permite crearla (esto solo nos sirve a la hora de ejecutarla en el servidor)
def create_app():

    #esta funcion carga todos las variables que esten en .env
    load_dotenv()
    app = Flask(__name__)

    #Conexion base de datos
    MONGO_URI = os.getenv("DB_HOST")
    app.secret_key = os.getenv("SECRET_KEY")
    client = MongoClient(MONGO_URI)
    db = client.get_database(os.getenv("DB_NAME"))
    users = db['users']
    # users = {"username":"Daron", "password":"daron"}
    # print(users["password"])

    # Esta funcion nos servira para comprobar si la sesion esta iniciada
    def comprobar_sesion():
        user = session.get('user')
        if not user:
            return redirect(url_for('logout'))



    @app.route("/", methods =['GET','POST'])
    def login():
        sesion = comprobar_sesion()
        if not sesion:
            flash('Ya tenia una sesion iniciada', 'info')
            sesion_user = session.get('user')
            return redirect(url_for('index', user=sesion_user))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = users.find_one({"username": username})
            if user:
                if pbkdf2_sha256.verify(password, user["password"]):
                    session['user'] = username
                    return redirect(url_for('index', user=user["username"]))
                else:
                    flash("Contraseña Incorrecta", 'danger')
            else:
                flash("Usuario incorrecto", 'danger')
        return render_template("login.html")

    @app.route("/index/<string:user>", methods =['GET', 'POST'])
    def index(user):
        # aqui captura la "redireccion" para que cuando el funcion retorne el comprobante no permita entrar en la pagina
        sesion = comprobar_sesion()
        if sesion:
            return sesion
    
        usuarios = users.find({})
        return render_template("index.html", usuarios = usuarios)

    @app.route("/register", methods = ['GET', 'POST'])
    def register():
        sesion = comprobar_sesion()
        if not sesion:
            session.clear()
            flash('Ya tenia una sesion iniciada', 'info')
            return redirect(url_for('login'))

        if request.method == 'POST':
            username = request.form['username']
            password = pbkdf2_sha256.hash(request.form['password'])
            user = users.find_one({"username": username})

            if not user:
                new_user = {"username": username, "password": password}
                users.insert_one(new_user)
                flash("Usuario creado con exito", 'primary')
                return redirect(url_for('login'))
            else:
                flash("Usuario ya creado", 'danger')
                
        
        return render_template("register.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash('Ha cerrado la sesión', 'info')
        return redirect(url_for('login'))

    @app.route("/update/<string:user_id>", methods = ['GET', 'POST'])
    def update(user_id):
        sesion = comprobar_sesion()
        if sesion:
            return sesion
        sesion_user = session.get('user')

        try:
            # Convertir user_id a ObjectId
            user_edit = users.find_one({"_id": ObjectId(user_id)})

        except Exception as e:
            flash("Error al procesar el ID del usuario", "danger")
            return redirect(url_for('index', user=sesion_user))
        
        if request.method == 'POST':
            username = request.form['username']
            password = pbkdf2_sha256.hash(request.form['password'])
            user = users.find_one({"username": username})
            if not user:
                data_update = {"$set": {"username": username, "password": password}}
                myquery = {"username": user_edit['username'], "password": user_edit['password']}
                users.update_one(myquery, data_update)
                return redirect(url_for('index', user=sesion_user))
            else:
                flash("Este usuario ya existe")
                return redirect(url_for('index', user=sesion_user))

        return render_template("update.html", user_id = user_id, user_edit = user_edit, user = sesion_user)

    @app.route("/delete/<string:user_id>", methods = ['POST'])
    def delete_user(user_id):
        sesion = comprobar_sesion()
        if sesion:
            return sesion
        sesion_user = session.get('user')

        try:
            # Convertir user_id a ObjectId
            user_delete = users.find_one({"_id": ObjectId(user_id)})

        except Exception as e:
            flash("Error al procesar el ID del usuario", "danger")
            return redirect(url_for('index', user=sesion_user))

        if request.method == 'POST':
            users.delete_one(user_delete)
            return url_for('index', user = sesion_user)


    @app.route("/create", methods = ['POST', 'GET'])
    def create():
        sesion = comprobar_sesion()
        if sesion:
            return sesion
        sesion_user = session.get('user')

        if request.method == 'POST':
            username = request.form['username']
            password = pbkdf2_sha256.hash(request.form['password'])
            user = users.find_one({"username": username})
            if not user:
                new_user = {"username": username, "password": password}
                users.insert_one(new_user)
                flash("Usuario creado con exito", 'primary')
                return redirect(url_for('index', user=sesion_user))
            else:
                flash("Este usuario ya existe")
                return redirect(url_for('create', user=sesion_user))

        return render_template("create.html", user = sesion_user)
    return app
    

if __name__=="__main__":
    app = create_app()
    app.run(debug=True)