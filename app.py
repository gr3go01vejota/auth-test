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
