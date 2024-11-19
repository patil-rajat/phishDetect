from flask import Flask, request, render_template
import pickle
import numpy as np
from feature_extraction import featureExtraction

app = Flask(__name__)

PORT = 8000

with open('./model/optimized_xgboost_model.pkl', 'rb') as file:
    model = pickle.load(file)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url'] 
        try:
            # extract features from the URL
            features = featureExtraction(url, label=None, output_file=None)
            
            # convert features to the proper format of the model
            input_features = np.array(features[1:-1]).reshape(1, -1)  # Exclude domain and label
            
            # prediction
            prediction = model.predict(input_features)[0]
            result = "Phishing" if prediction == 1 else "Benign"
            
            # display the submitted URL and the prediction result to the .html
            return render_template('index.html', prediction_text=f"The URL is classified as: {result}", submitted_url=url)
        
        except Exception as e:
            return render_template('index.html', prediction_text="Error processing the URL. Please try again.", submitted_url=url)

# make use of gpt api for creating a bot.
@app.route('/safeBot', methods=['GET', 'POST'])
def bot():
    pass

if __name__ == '__main__':
    app.run(port=PORT, debug=True)
