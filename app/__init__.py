from flask import Flask
from app.models import db
import os

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Configure SQLite Database
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, '..', 'phishguard.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
    # Register Blueprints
    from app.routes.ui_routes import ui_bp
    from app.routes.api_routes import api_bp
    
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    return app
