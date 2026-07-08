from flask import Blueprint, render_template
from app.models import ScanHistory
from app.utils.logger import logger

ui_bp = Blueprint('ui_routes', __name__)

@ui_bp.route('/', methods=['GET'])
def index():
    recent_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()
    return render_template('index.html', recent_scans=[scan.to_dict() for scan in recent_scans])

@ui_bp.route('/result', methods=['GET'])
def result():
    # We will handle results via SPA dynamics in index.html, 
    # but this route is kept just in case of direct access.
    return render_template('index.html')
