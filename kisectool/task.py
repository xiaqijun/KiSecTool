from . import db, portscan,producer,scheduler
from .model import Asset, Asset_port
def create_ip_task(ip):
    print('开始扫描')
    result_file=portscan.create_task(ip)
    #读取扫描结果，将结果存入数据库
    with open(result_file,'r') as f:
        for line in f:
            line=line.strip()#去掉行尾的换行符
            if line:
                line_list=line.split('\t')#按制表符分割
                ip=line_list[0]
                port=line_list[1]
                service=line_list[3]
                title=line_list[4]
            with scheduler.app.app_context():
                if not Asset.query.filter_by(ip=ip).first():
                    asset=Asset(ip=ip)
                    db.session.add(asset)
                    db.session.commit()
                asset=Asset.query.filter_by(ip=ip).first()
                if not Asset_port.query.filter_by(asset_id=asset.id,port=port).first():
                    asset_port=Asset_port(port=port,service=service,title=title,asset_id=asset.id)
                    db.session.add(asset_port)
                    db.session.commit()
            if service=='http' or service=='https':
                producer.send('http_port',value={'ip':ip,'port':port,'title':title})
            if service=='ssh' or service=='ftp' or service=='telnet' or service=='mysql':
                producer.send('weak_password',value={'ip':ip,'port':port,'title':title})