from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
from portscan.scan import Portscan
portscan=Portscan()
scheduler=APScheduler()
db=SQLAlchemy()
migrate=Migrate()
def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('../config.py')
    db.init_app(app)
    migrate.init_app(app,db)
    if scheduler.state == 0:
        scheduler.init_app(app)
        scheduler.start()
    return app