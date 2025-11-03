from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///auth.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "270fc1771a9c225c98b8d188ebf4710750895dd315adb51a"

db = SQLAlchemy(app)


class User(db.Model):
    """
    Representa um usuário no sistema.
    Campos:
    - id: inteiro, chave primária (gerado automaticamente)
    - username: texto curto, único (não pode repetir)
    - email: texto, único
    - password_hash: hash da senha (nunca armazenar senha pura)
    Métodos:
    - set_password: recebe a senha em texto e guarda apenas o hash
    - check_password: valida uma senha comparando com o hash salvo
    """

    id = db.Collumn(db.Iterger, primary_key=True)  # chave primaria
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullanle=False)

    def set_password(self, password: str) -> None:
        # Gera e armazena o hash da senha fornecida.
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        # Compara a senha fornecida com o hash salvo e retorna True/False.
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


@app.before_first_request
def create_table() -> None:
    """Garante que as tabelas existam antes da primeira requisição"""
    db.create_all()


@app.route("/")
def home():
    """Página inicial. Mostra se o usuário está logado ou não."""
    username = session.get("username")  # pega da sessão (se existir)
    return render_template("home.html", username=username)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Cadastro de usuário novo.
    GET -> mostra o formulário
    POST -> recebe os dados do formulário e cria o usuário
    """
    if request.method == "POST":
        if not username or not email or not password:
            flash("Preencha todos os campos.", "error")
            return render_template("register.html")
        if len(password) < 6:
            flash("Senha muito curta (mínimo 6 caracteres).", "error")
            return render_template("register.html")

        # Verifica se já existe usuário ou e-mail igual (restrição de unicidade)
        exists = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if exists:
            flash("Usuário ou e-mail já cadastrado.", "error")
            return render_template("register.html")

        # Cria e salva o novo usuário (armazenando apenas o hash da senha)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Cadastro realizado! Faça login.", "success")
        return redirect(url_for("login"))

    # Se for GET, apenas renderiza o formulário
    return render_template("register.html")
