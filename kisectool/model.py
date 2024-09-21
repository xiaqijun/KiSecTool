from . import db
class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), unique=True, nullable=False)
    os = db.Column(db.String(64), nullable=True)
    asset_ports = db.relationship('Asset_port', backref=db.backref('asset', lazy=True))

class Asset_port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    port = db.Column(db.Integer, nullable=False)
    service = db.Column(db.String(64), nullable=True)
    title=db.Column(db.String(64),nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'))
    

