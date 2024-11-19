# Phishing Detection Using Machine Learning

This project uses machine learning techniques to detect phishing URLs. The goal is to classify URLs as either **phishing** or **benign** based on their features. The machine learning model has been trained using a dataset of malicious and benign URLs and is deployed using a Flask web application.

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
- [Model Details](#model-details)
- [Folder Structure](#folder-structure)
- [Contributing](#contributing)
- [License](#license)

## Project Overview

Phishing attacks are a common threat to online security, where attackers attempt to deceive users into revealing sensitive information by impersonating legitimate websites. This project aims to detect phishing URLs through a machine learning model that analyzes features of URLs and classifies them accordingly. SVM, MLP, Random forest, decision tree, XGBoost are trained. Best model was used for deployment. 

### How It Works:
1. **Feature Extraction:** Features are extracted from the URLs using specific methods that analyze their structure and content.
2. **Machine Learning Model:** The extracted features are used to train a machine learning model (XGBoost) to classify URLs.
3. **Flask Web Application:** A Flask app provides an interface for users to input a URL and get the classification result.

## Features
- **URL Classification:** Classify a given URL as either **Phishing** or **Benign**.
- **Model Deployment:** Hosted in a Flask web application for easy access.
- **Real-time Detection:** Classify URLs in real-time by pasting them into the web interface.

## Getting Started

### Prerequisites

Ensure that you have met the following requirements:
- **Python 3.x** or higher
- **pip** (Python package installer)

### Installation

Follow these steps to set up the project:

1. Clone the repo:
   ```bash
   git clone https://github.com/patil-rajat/phishing-detection.git
   cd phishing-detection

2. Setup a Virtual Environment:
   ```
   python -m venv venv
   source venv/bin/activate  # For Linux/MacOS
   venv\Scripts\activate     # For Windows
   
3. Install the required dependancies:
   ```
   pip install -r requirements.txt
   
4. To run the app:
   ```
   cd applicationFlask
   python app.py

## Model Details
The machine learning model used for URL classification is XGBoost, a powerful gradient boosting algorithm. It has been trained to analyze features extracted from URLs and classify them into two categories: Phishing and Benign.
1. **Model Type: XGBoost (Gradient Boosting Model)
2. **Training Data: A dataset of URLs labeled as either phishing or benign.
3. **Model Serialization: The trained model is serialized and stored in a .pkl file for easy loading during predictions.
