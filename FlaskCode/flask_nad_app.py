from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

# encoders and scalers
encoder_dict = joblib.load('m1_labelencoder.pkl')
scaler_dict = joblib.load('m1_scaler.pkl')
target_encoder = joblib.load('m2_targetlabelencoder.pkl')
target_classes = joblib.load('m2_targetclasses.pkl')
target_classes2 = np.array([target_encoder.classes_[i] for i in range(len(target_encoder.classes_))])

#triple model stage 1
triple_model1 = joblib.load('triple_model_all1.pkl')
triple_encoder_dict = joblib.load('triple_m1_labelencoder.pkl')
triple_scaler = joblib.load('triple_m1_scaler.pkl')

# triple model stage 2
triple_model2 = joblib.load('triple_model_all2.pkl')
triple_target = joblib.load('triple_m2_all_targetencoder.pkl')
triple_target_classes2 = np.array([triple_target.classes_[i] for i in range(len(triple_target.classes_))])

# triple model stage 3
triple_dos_encoder = joblib.load('triple_m3_all_dos_encoder.pkl')
triple_dos_model = joblib.load('triple_m3_all_dos_model.pkl')

triple_scan_encoder = joblib.load('triple_m3_all_scan_encoder.pkl')
triple_scan_model = joblib.load('triple_m3_all_scan_model.pkl')

triple_access_encoder = joblib.load('triple_m3_all_access_encoder.pkl')
triple_access_model = joblib.load('triple_m3_all_access_model.pkl')

triple_back_encoder = joblib.load('triple_m3_all_back_encoder.pkl')
triple_back_model = joblib.load('triple_m3_all_back_model.pkl')

triple_exploit_encoder = joblib.load('triple_m3_all_exploit_encoder.pkl')
triple_exploit_model = joblib.load('triple_m3_all_exploit_model.pkl')

triple_dos_classes = triple_dos_encoder.classes_
triple_scan_classes = triple_scan_encoder.classes_
triple_access_classes = triple_access_encoder.classes_
triple_back_classes = triple_back_encoder.classes_
triple_exploit_classes = triple_exploit_encoder.classes_


#columns to encode
categorical_columns = ['protocoltype', 'service', 'flag','land','wrongfragment','urgent','loggedin','rootshell','suattempted','numshells',
                       'ishostlogin','isguestlogin']

numeric_columns = ['duration', 'srcbytes', 'dstbytes', 'hot', 'numfailedlogins','numcompromised', 'numroot', 'numfilecreations', 'numaccessfiles',
       'numoutboundcmds', 'count', 'srvcount', 'serrorrate', 'srvserrorrate','rerrorrate', 'srvrerrorrate', 'samesrvrate', 'diffsrvrate',
       'srvdiffhostrate', 'dsthostcount', 'dsthostsrvcount','dsthostsamesrvrate', 'dsthostdiffsrvrate', 'dsthostsamesrcportrate',
       'dsthostsrvdiffhostrate', 'dsthostserrorrate', 'dsthostsrvserrorrate','dsthostrerrorrate', 'dsthostsrvrerrorrate', 'lastflag',
       'serror', 'rerror', 'srvserror', 'srvrerror', 'samesrv', 'diffsrv','dsthostserror', 'dsthostrerror', 'dsthostsrvserror',
       'dsthostsrvrerror', 'dsthostsamesrv', 'dsthostdiffsrv']

app = Flask(__name__)
app.secret_key = "ANYEPSKISALMHRTHAPDKFJEISJ"


@app.route('/networkrequest',methods=['GET','POST'])
def networkrequest():
   recv_data = pd.DataFrame(request.get_json(),index=[0])
   #print(target_classes)
   print(recv_data)
   for col in categorical_columns:
       enc = encoder_dict[col]
       recv_data[col] = enc.transform(recv_data[col])

   recv_data[numeric_columns] = scaler_dict.transform(recv_data[numeric_columns])
   #print(recv_data)
   if 'serror' not in recv_data.columns:
      recv_data['serror'] = recv_data['count']*recv_data['serrorrate']
   if 'rerror' not in recv_data.columns:
      recv_data['rerror'] = recv_data['count']*recv_data['rerrorrate']
   if 'srvserror' not in recv_data.columns:
      recv_data['srvserror'] = recv_data['srvcount']*recv_data['srvrerrorrate']
   if 'srvrerror' not in recv_data.columns:
       recv_data['srvrerror'] = recv_data['srvcount']*recv_data['srvserrorrate']
   if 'samesrv' not in recv_data.columns:
       recv_data['samesrv'] = recv_data['count']*recv_data['samesrvrate']
   if 'diffsrv' not in recv_data.columns:
        recv_data['diffsrv'] = recv_data['count']*recv_data['diffsrvrate']
   if 'dsthostserror' not in recv_data.columns:
        recv_data['dsthostserror'] = recv_data['dsthostcount']*recv_data['dsthostserrorrate']
   if 'dsthostrerror' not in recv_data.columns:
        recv_data['dsthostrerror'] = recv_data['dsthostcount']*recv_data['dsthostrerrorrate']
   if 'dsthostsrvserror' not in recv_data.columns:
        recv_data['dsthostsrvserror'] = recv_data['dsthostsrvcount']*recv_data['dsthostsrvrerrorrate']
   if 'dsthostsrvrerror' not in recv_data.columns:
        recv_data['dsthostsrvrerror'] = recv_data['dsthostsrvcount']*recv_data['dsthostsrvserrorrate']
   if 'dsthostsamesrv' not in recv_data.columns:
        recv_data['dsthostsamesrv'] = recv_data['dsthostsrvcount']*recv_data['dsthostsamesrvrate']
   if 'dsthostdiffsrv' not in recv_data.columns:
        recv_data['dsthostdiffsrv'] = recv_data['dsthostsrvcount']*recv_data['dsthostdiffsrvrate']

   model1 = joblib.load('model1.pkl')
   y_pred = model1.predict(recv_data)
   print(y_pred)
   
   if y_pred[0] == 1:
       model2 = joblib.load('model2.pkl')
       y_pred2 = model2.predict(recv_data)
       print(y_pred2)
       #print(target_classes[y_pred2])
       print(target_classes2[y_pred2])
   
   return render_template('networkrequest.html')


@app.route('/networkrequestthree',methods=['GET','POST'])
def networkrequestthree():
   recv_data = pd.DataFrame(request.get_json(),index=[0])
   
   if 'serror' not in recv_data.columns:
      recv_data['serror'] = recv_data['count']*recv_data['serrorrate']
   if 'rerror' not in recv_data.columns:
      recv_data['rerror'] = recv_data['count']*recv_data['rerrorrate']
   if 'srvserror' not in recv_data.columns:
      recv_data['srvserror'] = recv_data['srvcount']*recv_data['srvrerrorrate']
   if 'srvrerror' not in recv_data.columns:
       recv_data['srvrerror'] = recv_data['srvcount']*recv_data['srvserrorrate']
   if 'samesrv' not in recv_data.columns:
       recv_data['samesrv'] = recv_data['count']*recv_data['samesrvrate']
   if 'diffsrv' not in recv_data.columns:
        recv_data['diffsrv'] = recv_data['count']*recv_data['diffsrvrate']
   if 'dsthostserror' not in recv_data.columns:
        recv_data['dsthostserror'] = recv_data['dsthostcount']*recv_data['dsthostserrorrate']
   if 'dsthostrerror' not in recv_data.columns:
        recv_data['dsthostrerror'] = recv_data['dsthostcount']*recv_data['dsthostrerrorrate']
   if 'dsthostsrvserror' not in recv_data.columns:
        recv_data['dsthostsrvserror'] = recv_data['dsthostsrvcount']*recv_data['dsthostsrvrerrorrate']
   if 'dsthostsrvrerror' not in recv_data.columns:
        recv_data['dsthostsrvrerror'] = recv_data['dsthostsrvcount']*recv_data['dsthostsrvserrorrate']
   if 'dsthostsamesrv' not in recv_data.columns:
        recv_data['dsthostsamesrv'] = recv_data['dsthostsrvcount']*recv_data['dsthostsamesrvrate']
   if 'dsthostdiffsrv' not in recv_data.columns:
        recv_data['dsthostdiffsrv'] = recv_data['dsthostsrvcount']*recv_data['dsthostdiffsrvrate']
    

   for col in categorical_columns:
       enc = encoder_dict[col]
       recv_data[col] = enc.transform(recv_data[col])

   recv_data[numeric_columns] = scaler_dict.transform(recv_data[numeric_columns])

   y_pred1 = triple_model1.predict(recv_data)
   y_pred2 = None
   y_pred3 = None
   if y_pred1[0] == 1:
       y_pred2 = triple_target_classes2[triple_model2.predict(recv_data)]
       if y_pred2 == 'dos':
           y_pred3 = triple_dos_classes[triple_dos_model.predict(recv_data)]
       elif y_pred2 == 'scan':
           y_pred3 = triple_scan_classes[triple_scan_model.predict(recv_data)]
       elif y_pred2 == 'access':
           y_pred3 = triple_access_classes[triple_access_model.predict(recv_data)]
       elif y_pred2 == 'backdoor':
           y_pred3 = triple_back_model.predict(recv_data)
       else:
           y_pred3 = triple_exploit_classes[triple_exploit_model.predict(recv_data)]
           
       

   return {'is_attack':str(y_pred1),'attack_category':str(y_pred2),'attack':str(y_pred3)}


if __name__ == "__main__":
    app.run(debug=True)
