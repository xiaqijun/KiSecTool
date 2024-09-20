from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
from portscan.scan import Portscan
from kafka import KafkaProducer, KafkaConsumer
import json
portscan=Portscan()
db=SQLAlchemy()
migrate=Migrate()
scheduler=APScheduler()
producer = KafkaProducer(
    bootstrap_servers=["1Panel-kafka-Q26n:9092"],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)
consumer_ip=KafkaConsumer(
    "ip",
    bootstrap_servers=["192.168.154.128:9092"],
    group_id="ip_group",
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    auto_offset_reset='earliest',
    enable_auto_commit=True
)
consumer_main_domain=KafkaConsumer(
    "main_domain",
    bootstrap_servers=["192.168.154.128:9092"],
    group_id="main_domain_group",
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    auto_offset_reset='earliest',
    enable_auto_commit=True
)
consumer_sub_domain=KafkaConsumer(
    "sub_domain",
    bootstrap_servers=["192.168.154.128:9092"],
    group_id="sub_domain_group",
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    auto_offset_reset='earliest',
    enable_auto_commit=True
)
consumer_weak_password=KafkaConsumer(
    "weak_password",
    bootstrap_servers=["192.168.154.128:9092"],
    group_id="weak_password_group",
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    auto_offset_reset='earliest',
    enable_auto_commit=True
)
consumer_http_port=KafkaConsumer(
    "http_port",
    bootstrap_servers=["192.168.154.128:9092"],
    group_id="http_port_group",
    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
    auto_offset_reset='earliest',
    enable_auto_commit=True
)
def start_consumer_ip():
    for message in consumer_ip:
        ip=message.value

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('../config.py')
    db.init_app(app)
    migrate.init_app(app,db)
    if scheduler.state == 0:
        scheduler.init_app(app)
        scheduler.start()
    portscan.create_task('1')
    from .asset_scan import asset_scan_bp
    app.register_blueprint(asset_scan_bp)
    return app