# Network_Anomaly_Detection
 A repo containing end to end implementation of Network Anomaly Detection.
 
Oultine
In cybersecurity, network anomaly detection is a critical task that involves identifying unusual patterns or 
behaviours that deviate from the norm within network traffic. Traditional methods of network anomaly detection
often rely on predefined rules or signatures based on known attack patterns.

However, these methods fall short of detecting new or evolving threats that do not match the existing 
signatures. Furthermore, as network environments grow in complexity, maintaining and updating these rules 
becomes increasingly cumbersome and less effective.

Problem Statement
The goal is to develop an approach where, the focus is on leveraging machine learning techniques to analyse 
network traffic and detect deviations from normal behaviour. This approach allows for dynamic adaptation to new,
evolving threats while reducing the complexity of managing static security rules. Our end goal is to employ ML
models that will learn patterns of network traffic and can identify potential anomalies and predict emerging 
security risks in real-time.


We have categorized the files into the following folders:
1) EDA
2) Hypothesis testing
3) Machine Learning
4) Flask Code
5) Pickle Files

For hypothesis test run NAD_hypothesis_final to check all the different hypothesis tests performed.
Run the cascade model8 file to get the F1 score at 0.975.

For deployment, use the pickle files along with the flask file flask_nad_app.py.
Create a pythone venv and run the requirements.txt file. 
Now run the flask app and you can send requests to this via postman.

