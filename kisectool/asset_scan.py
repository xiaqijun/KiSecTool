from flask import Flask, Blueprint, request, jsonify
from .model import Asset, Asset_port
from . import db, portscan
from . import scheduler
from datetime import datetime
import os
asset_scan_bp = Blueprint('asset_scan', __name__)
@asset_scan_bp.route('/create_asset_scan_task', methods=['POST'])
def create_asset_scan_task():
    ip_list = request.json.get('ip_list')
    port_text = request.json.get('port_list')
    if not ip_list or not port_text:
        return jsonify({'code': 400, 'msg': '参数错误'})
    tmp_dir = os.path.join(os.getcwd(), 'tmp')
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    ip_file_name = os.path.join(tmp_dir, 'ip{}.txt'.format(datetime.now().strftime('%Y%m%d%H%M%S')))
    port_file_name = os.path.join(tmp_dir, 'port{}.txt'.format(datetime.now().strftime('%Y%m%d%H%M%S')))
    with open(ip_file_name,'w') as f:
        for ip in ip_list:
            f.write(ip+'\n')
    with open(port_file_name,'w') as f:
        f.write(port_text)
    result_file_name = os.path.join(tmp_dir, 'result{}.txt'.format(datetime.now().strftime('%Y%m%d%H%M%S')))
    task = scheduler.add_job(func=portscan.chuli_canshu, args=(ip_file_name,port_file_name,'',1,3,10,result_file_name), trigger='date', run_date=datetime.now())
    return jsonify({'code': 200, 'msg': '任务创建成功'})
