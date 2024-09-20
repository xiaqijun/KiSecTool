from flask import Flask, Blueprint, request, jsonify,template_rendered
from .model import Asset, Asset_port
from . import db, portscan
from datetime import datetime
import os
asset_scan_bp = Blueprint('asset_scan', __name__)
@asset_scan_bp.route('/scan', methods=['GET'])
def scan():
    return template_rendered('scan.html')