from flask import Flask, request, render_template
import pickle
import numpy as np
from feature_extraction import featureExtraction
import json
import requests
import os
import csv
import time

app = Flask(__name__)
PORT = 8000

INSPECTED_URLS_FILE = 'inspected_urls.csv'

with open('./model/optimized_xgboost_model.pkl', 'rb') as file:
    model = pickle.load(file)


def loader(file_path="config.json"):
    try:
        with open(file_path, "r") as file:
            config = json.load(file)
            return config["source"]
    except FileNotFoundError:
        raise FileNotFoundError("The config file is missing.")
    except KeyError:
        raise KeyError("The source is missing in the config file.")
    except json.JSONDecodeError:
        raise ValueError("The config file contains invalid JSON.")


KEY_LOADER = loader()

def query_virustotal(url):
    try:
        vt_submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": KEY_LOADER}

        # Submit URL
        response = requests.post(vt_submit_url, headers=headers, data={"url": url})
        if response.status_code != 200:
            return {"error": f"Error submitting URL: {response.status_code}"}

        analysis_id = response.json().get("data", {}).get("id")
        print("analysis id: ",analysis_id)
        if not analysis_id:
            return {"error": "Failed to retrieve Analysis ID from VirusTotal."}

        # Wait for analysis to complete
        print("waiting for 20 sec")
        time.sleep(20)  # Delay for 20 seconds


        # Retrieve analysis
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)

        # polling
        # for _ in range(6):  # Check every 5 seconds, max 30 seconds
        #     analysis_response = requests.get(analysis_url, headers=headers)
        #     if analysis_response.status_code == 200:
        #         analysis_data = analysis_response.json()
        #         if analysis_data.get("data", {}).get("attributes", {}).get("status") == "completed":
        #             break
        #     time.sleep(5)

        if analysis_response.status_code != 200:
            return {"error": f"Error retrieving analysis: {analysis_response.status_code}"}

        analysis_data = analysis_response.json()
        # remove this in prod
        # print("Analysis Response JSON:", analysis_response.json())
        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        # stats = analysis_data.get("data", {}).get("stats", {})
        print("STATS: ",stats)
        return {
            "analysis_id": analysis_id,
            "stats": {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            },
        }
    except Exception as e:
        return {"error": str(e)}


def store_inspected_url(url, analysis_id, classification, risk_level, confidence_score, vt_stats):
    file_exists = os.path.isfile(INSPECTED_URLS_FILE)
    with open(INSPECTED_URLS_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow([
                'URL', 'Analysis ID', 'Classification', 
                'Risk Level', 'Confidence score', 'Harmless',
                'Malicious','Suspicious','Undetected'
            ])
        # writer.writerow([url, analysis_id, classification, risk_level])
        writer.writerow([
            url, analysis_id, classification, 
            risk_level, f"{confidence_score:.2f}",
            vt_stats.get("harmless", 0),
            vt_stats.get("malicious", 0),
            vt_stats.get("suspicious", 0),
            vt_stats.get("undetected", 0),
        ])


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

'''
    the /predict handles the prediction
'''
@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        try:
            # step 1 - extract features and make prediction using the ML model
            features = featureExtraction(url, label=None, output_file=None)
            input_features = np.array(features[1:-1]).reshape(1, -1)
            prediction = model.predict(input_features)[0]
            confidence_score = model.predict_proba(input_features)[0][prediction]
            # classification = "Phishing" if prediction == 1 else "Benign"
            if prediction == 1:
                classification = "Phishing" 
            else:
                classification = "Benign"

            # step 2 - query virustotal
            vt_result = query_virustotal(url)
            vt_stats = vt_result.get("stats", {})
            # remove this
            print("VirusTotal Stats:", vt_stats)
            analysis_id = vt_result.get("analysis_id", "N/A")

            # step 3 - combine results and determine classification
            if (prediction == 1 and confidence_score > 0.75 and vt_stats.get("malicious", 0) > 50):
                final_classification = "Phishing"
                risk_level = "Severe"
            elif (prediction == 0 and confidence_score > 0.75 and vt_stats.get("harmless", 0) > 50):
                final_classification = "Benign"
                risk_level = "Low"
            else:
                final_classification = "Uncertain"
                risk_level = "Moderate"

            # step 4 - store results in CSV
            # store_inspected_url(url, analysis_id, final_classification, risk_level)
            store_inspected_url(
                url=url,
                analysis_id=analysis_id,
                classification=final_classification,
                risk_level=risk_level,
                confidence_score=confidence_score,
                vt_stats=vt_stats,
            )

            # step 5 - display results to the user
            print("Data sent to template:", {
                "prediction_text": classification,
                "risk_level_text": risk_level,
                "vt_analysis": vt_stats,
                "confidence_score": confidence_score,
                "submitted_url": url,
            })
            return render_template(
                'index.html',
                prediction_text=f"{classification}",            # classification
                risk_level_text=f"{risk_level}",                # risklevel calculation result
                vt_analysis=vt_stats,                           # analysis result
                confidence_score=f"{confidence_score:.2f}",     # confidence score
                submitted_url=url,
            )
        except Exception as e:
            return render_template(
                'index.html',
                prediction_text="Error processing the URL. Please try again.",
                error_message=str(e),
            )


if __name__ == '__main__':
    app.run(port=PORT, debug=True)
