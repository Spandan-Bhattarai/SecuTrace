"""
SOAR - Security Orchestration, Automation and Response Tool
Main Flask application for threat intelligence gathering
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from services.threat_intel import ThreatIntelService

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Initialize threat intel service
threat_intel = ThreatIntelService()


@app.route('/')
def index():
    """Render main dashboard"""
    return render_template('index.html')


@app.route('/about')
def about():
    """Render about page"""
    return render_template('about.html')


@app.route('/privacy')
def privacy():
    """Render privacy policy page"""
    return render_template('privacy.html')


@app.route('/cookies')
def cookies():
    """Render cookie policy page"""
    return render_template('cookies.html')


@app.route('/terms')
def terms():
    """Render terms of service page"""
    return render_template('terms.html')


@app.route('/api/lookup', methods=['POST'])
def lookup():
    """
    Lookup an IP address or domain across all threat intelligence sources
    """
    data = request.get_json()
    indicator = data.get('indicator', '').strip()
    
    if not indicator:
        return jsonify({'error': 'No indicator provided'}), 400
    
    # Determine indicator type
    indicator_type = threat_intel.detect_indicator_type(indicator)
    
    # Run all lookups
    results = threat_intel.lookup_all(indicator, indicator_type)
    
    return jsonify({
        'indicator': indicator,
        'type': indicator_type,
        'results': results
    })


@app.route('/api/lookup/<source>', methods=['POST'])
def lookup_single(source):
    """
    Lookup an indicator on a specific source
    """
    data = request.get_json()
    indicator = data.get('indicator', '').strip()
    
    if not indicator:
        return jsonify({'error': 'No indicator provided'}), 400
    
    indicator_type = threat_intel.detect_indicator_type(indicator)
    result = threat_intel.lookup_single(indicator, indicator_type, source)
    
    return jsonify({
        'indicator': indicator,
        'type': indicator_type,
        'source': source,
        'result': result
    })


@app.route('/api/sources', methods=['GET'])
def get_sources():
    """Get list of available threat intelligence sources and their status"""
    return jsonify(threat_intel.get_sources_status())


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
