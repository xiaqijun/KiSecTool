from flask import Flask, Blueprint, request, jsonify,render_template
from .model import Asset, Asset_port
from . import db, portscan,producer,consumer_ip,consumer_main_domain,consumer_sub_domain,consumer_weak_password,consumer_http_port
from datetime import datetime
import re
import os
import socket

asset_scan_bp = Blueprint('asset_scan', __name__)
@asset_scan_bp.route('/scan', methods=['GET'])
def scan():
    return render_template('scan.html')

@asset_scan_bp.route('/add_scan', methods=['POST'])
def add_scan():
    ip_domain_list=request.json.get('ip_domain_list')
    try:
        for ip_domain in ip_domain_list:
            if check_ip_or_domain(ip_domain)==1:
                producer.send('ip', value=ip_domain)
            elif check_ip_or_domain(ip_domain)==2:
                producer.send('sub_domain', value=ip_domain)
                try:
                    resolved_ip = socket.gethostbyname(ip_domain)
                    producer.send('ip', value=resolved_ip)
                except Exception as e:
                    print(e)
            elif check_ip_or_domain(ip_domain)==3:
                producer.send('main_domain', value=ip_domain)
        return jsonify({'msg':'success'})
    except Exception as e:
        return jsonify({'msg':str(e)})

def check_ip_or_domain(ip_domain):
    """
    检查输入是IP地址、域名还是子域名。
    
    Args:
        ip_domain (str): 输入的IP地址或域名。
        
    Returns:
        int: 1 表示IP地址, 2 表示子域名, 3 表示域名, 0 表示无效的输入。
    """
    # 正则表达式用于匹配IPv4地址
    ip_pattern = re.compile(r'^((25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.){3}(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})$')
    
    # 正则表达式用于匹配域名（包括子域名）
    domain_pattern = re.compile(r'^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$')
    
    # 检查是否是有效的IP地址
    if ip_pattern.match(ip_domain):
        return 1  # 返回1表示IP地址
    
    # 检查是否是有效的域名或子域名
    elif domain_pattern.match(ip_domain):
        # 如果有多个部分，说明是子域名
        if ip_domain.count('.') > 1:
            return 2  # 返回2表示子域名
        else:
            return 3  # 返回3表示普通域名
    
    # 都不是则返回0表示无效
    else:
        return 0