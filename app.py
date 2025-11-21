from flask import Flask, request, jsonify
from flask_cors import CORS
import pyclamd
import os
import tempfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
MAX_FILE_SIZE = 30 * 1024 * 1024  # 30MB
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 
    'zip', 'rar', 'exe', 'msi', 'bat', 'cmd', 'js', 'vbs', 'ps1'
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def connect_to_clamav():
    try:
        # Try connecting to ClamAV daemon (TCP socket)
        cd = pyclamd.ClamdNetworkSocket()
        cd.ping()
        return cd
    except pyclamd.ConnectionError:
        try:
            # Fall back to local Unix socket
            cd = pyclamd.ClamdUnixSocket()
            cd.ping()
            return cd
        except pyclamd.ConnectionError:
            # Fall back to in-memory scanning
            return pyclamd.ClamdAgnostic()

@app.route('/scan', methods=['POST'])
def scan_file():
    # Check if a file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # Check if filename is empty
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file size
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)
    
    if file_length > MAX_FILE_SIZE:
        return jsonify({'error': f'File size exceeds {MAX_FILE_SIZE // (1024*1024)}MB limit'}), 400
    
    # Validate file type
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Secure the filename
    filename = secure_filename(file.filename)
    
    # Save the file temporarily
    temp_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(temp_path)
    
    try:
        # Connect to ClamAV
        cd = connect_to_clamav()
        
        # Scan the file
        scan_result = cd.scan_file(temp_path)
        
        # Clean up temporary file
        os.remove(temp_path)
        
        if scan_result is None:
            # No threats found
            return jsonify({
                'is_malicious': False,
                'message': 'File is clean',
                'engine_version': cd.version()
            })
        else:
            # Threat detected
            threat_name = list(scan_result.values())[0][1]
            return jsonify({
                'is_malicious': True,
                'threat_name': threat_name,
                'message': 'Malicious file detected',
                'engine_version': cd.version()
            })
            
    except Exception as e:
        # Clean up temporary file in case of error
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    try:
        cd = connect_to_clamav()
        return jsonify({
            'status': 'healthy',
            'engine_version': cd.version()
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)