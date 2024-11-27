from flask import Flask, request, render_template
import pickle
import numpy as np
from feature_extraction import featureExtraction
import json
import requests
import os
import csv


app = Flask(__name__)
PORT = 8000

INSPECTED_URLS_FILE = './inspected_urls.csv'

with open('./model/optimized_xgboost_model.pkl', 'rb') as file:
    model = pickle.load(file)


# make use of gpt api for creating a bot.
# @app.route('/safeBot', methods=['GET', 'POST'])

# Load the API key from json
def load_api_key(file_path="config.json"):
    try:
        with open(file_path, "r") as file:
            config = json.load(file)
            return config["API_KEY"]
    except FileNotFoundError:
        raise FileNotFoundError("The config file is missing.")
    except KeyError:
        raise KeyError("The API KEY is missing in the config file.")
    except json.JSONDecodeError:
        raise ValueError("The config file contains invalid JSON.")


API_KEY = load_api_key()

def query_virustotal(url):
    ''' v1 
    try:
        headers = {'x-apikey': API_KEY}
        vt_url = "https://www.virustotal.com/api/v3/urls"
        
        # Encode the URL to the required format
        encoded_url = requests.utils.quote(url, safe='')
        response = requests.get(f"{vt_url}/{encoded_url}", headers=headers)
        vt_data = response.json()

        # Extract relevant details
        analysis_stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        categories = vt_data.get('data', {}).get('attributes', {}).get('categories', {})
        reputation = vt_data.get('data', {}).get('attributes', {}).get('reputation', 0)

        return {
            "analysis_stats": analysis_stats,
            "categories": categories,
            "reputation": reputation
        }
    except Exception as e:
        return {"error": str(e)}
    '''
    try:
        # VirusTotal API endpoints
        vt_submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": API_KEY}

        # Step 1: Submit the URL to VirusTotal
        response = requests.post(vt_submit_url, headers=headers, data={"url": url})
        if response.status_code != 200:
            return {"error": f"Error submitting URL: {response.status_code}"}

        analysis_id = response.json().get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to retrieve Analysis ID from VirusTotal."}

        # Step 2: Retrieve the analysis results using the Analysis ID
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code != 200:
            return {"error": f"Error retrieving analysis: {analysis_response.status_code}"}

        analysis_data = analysis_response.json()
        # Extract relevant details
        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        categories = analysis_data.get("data", {}).get("attributes", {}).get("categories", {})
        reputation = analysis_data.get("data", {}).get("attributes", {}).get("reputation", 0)

        return {
            "stats": stats,
            "categories": categories,
            "reputation": reputation,
        }

    except Exception as e:
        return {"error": str(e)}


# Function to store inspected URLs in a csv for future train 
def store_inspected_url(url, risk_level, classification):
    file_exists = os.path.isfile(INSPECTED_URLS_FILE)
    with open(INSPECTED_URLS_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            # Write headers if the file doesn't exist
            writer.writerow(['URL', 'Risk Level', 'Classification'])
        writer.writerow([url, risk_level, classification])


# main landing page
@app.route('/')
def home():
    return render_template('index.html')

# predict (on press of button)
@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url'] 
        try:
            ''' STEP 1  : MODEL '''
            # extract features from the URL
            features = featureExtraction(url, label=None, output_file=None)
            # convert features to the proper format of the model
            input_features = np.array(features[1:-1]).reshape(1, -1)  # Exclude domain and label
            # prediction
            prediction = model.predict(input_features)[0]
            #result == classification
            if prediction == 1:
                classification = "Phishing" 
            else:
                classification = "Benign"

            ''' STEP 2: VT '''
            # Step 2: Query VirusTotal API for additional details
            vt_result = query_virustotal(url)
            if "error" in vt_result:
                vt_analysis = {"details": "Unable to retrieve data from VirusTotal."}
            else:
                vt_analysis = {
                    "stats": vt_result.get("analysis_stats"),
                    "categories": vt_result.get("categories"),
                    "reputation": vt_result.get("reputation")
                }

            ''' STEP 3: Combine & compare results '''
            # Step 3: Combine results and determine risk level
            if prediction == 1 and vt_result.get("reputation", 0) < 0:
                risk_level = "High"
            elif prediction == 1 or vt_result.get("reputation", 0) < 0:
                risk_level = "Moderate"
            else:
                risk_level = "Low"

            '''STEP 4 : Store in csv for future use '''
            # print(vt_analysis)
            # Step 5: Display results to the user
            return render_template(
                'index.html',
                prediction_text=f"The URL is classified as: {classification}",
                risk_level_text=f"Risk Level: {risk_level}",
                vt_analysis=vt_analysis,
                submitted_url=url
            )    
        except Exception as e:
            return render_template('index.html', prediction_text="Error processing the URL. Please try again.", submitted_url=url)



if __name__ == '__main__':
    app.run(port=PORT, debug=True)
