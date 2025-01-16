from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt
app = Flask(__name__)
app.config["SECRET_KEY"] = "default"
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'
login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = "login"
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso."})
    return jsonify({"message": "Credenciais inválidas"}), 400
@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso."})
@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({"message": "Usuário já cadastrado."}), 400
        new_user = User(username=username, password=hashed_password, role="user")
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso."})
    return jsonify({"message": "Dados inválidos."}), 400
@app.route("/user/<int:id>", methods=["GET"])
@login_required
def read_user(id:int):
    user = User.query.get(id)
    if user:
        return jsonify({"username": user.username})
    return jsonify({"message": "Usuário não encontrado"}), 404
@app.route("/user/<int:id>", methods=["PUT"])
@login_required
def update_user(id:int):
    user = User.query.get(id)
    data = request.json
    password = data.get("password")
    if not user:
        return jsonify({"message": "Usuário não encontrado"}), 404
    
    if (user.id != current_user.id) and (current_user.role != "admin"):
        return jsonify({"message": "Operação não permitida."}), 403
    if not password:
        return jsonify({"message": "Senha não informada"})
    user.password = password
    db.session.commit()
    return jsonify({"message": f"Usuário {user.id} atualizado com sucesso."})
@app.route("/user/<int:id>", methods=["DELETE"])
@login_required
def delete_user(id:int):
    user = User.query.get(id)

    if not user:
        return jsonify({"message": "Usuário não encontrado"}), 404
    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403
    if user.id == current_user.id:
        return jsonify({"message": "Deleção não permitida."}), 403
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": f"Usuário {user.id} deletado com sucesso."})
if __name__ == "__main__":
    app.run(debug=True)