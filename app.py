from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# টিমের নাম ও লোগো
TEAM_NAME = "Cyber Annihilators BD"
TEAM_LOGO = "static/logo.png"  # লোগো path

# VirusTotal API কী
VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            headers = {"x-apikey": VT_API_KEY}
            response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                analysis_response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    stats = analysis_data['data']['attributes']['stats']
                    if stats['malicious'] > 0 or stats['suspicious'] > 0:
                        result = '⚠ Suspicious or Malicious URL detected!'
                    else:
                        result = '✅ URL looks safe'
                else:
                    result = 'Error fetching analysis result.'
            else:
                result = 'Error submitting URL to VirusTotal.'
        else:
            result = 'Please enter a valid URL.'
    return render_template('index.html', result=result, team_name=TEAM_NAME, team_logo=TEAM_LOGO)

if __name__ == '__main__':
    app.run(debug=True)