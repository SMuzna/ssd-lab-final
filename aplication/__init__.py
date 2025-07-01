from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import mysql.connector
import os
import logging


aplication = Flask(__name__)

# Basic Flask configuration
aplication.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
aplication.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:CostadoMarfimrx8*10@localhost:3306/info_dados_db'
aplication.config['SECRET_KEY'] = 'secret'

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'upload') # constante do endereço para armazenar a imagem

# Initialize database and login manager
login_manager = LoginManager(aplication)
db = SQLAlchemy(aplication)

limiter = Limiter(
    key_func=get_remote_address,
    app=aplication,
    default_limits=["200 per day", "50 per hour"],  # Default rate limits
    storage_uri="memory://",  # Use memory storage for rate limiting
)

csp = {
    'default-src': "'self'",  # to only allow resources from same origin preventing loadinf resources from external sources
    'script-src': ["'self'"],  # to disallow inline scripts and external JS
    'frame-ancestors': "'none'"  # to prevent iframe embedding
}


Talisman(
    aplication,
    content_security_policy=csp,
    force_https=False  # Set to True in production with HTTPS
)


logging.basicConfig(
    level=logging.WARNING,  # Only log warnings and errors
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Console output only
    ]
)
aplication.logger.setLevel(logging.WARNING)
