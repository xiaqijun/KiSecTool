from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
from portscan.scan import Portscan
from kafka import KafkaProducer, KafkaConsumer
import json
from datetime import datetime
from uuid import uuid4
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

@scheduler.task('date',id='consumer_ip')
def start_consumer_ip():
    print('开始消费')
    while True:
        message=consumer_ip.poll(timeout_ms=1000,max_records=1)
        if message:
            for topic_partition,records in message.items():
                for record in records:
                    ip=record.value
                    print(ip)
                    #创建任务
                    task_id=str(uuid4())
                    from .task import create_ip_task
                    scheduler.add_job(id=str(uuid4()),func=create_ip_task,args=(ip,),trigger='date',run_date=datetime.now())
                    print('创建任务',task_id)
def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('../config.py')
    db.init_app(app)
    migrate.init_app(app,db)
    if scheduler.state == 0:
        scheduler.init_app(app)
        scheduler.start()
    scheduler.remove_all_jobs()
    from .asset_scan import asset_scan_bp
    app.register_blueprint(asset_scan_bp)
    return app