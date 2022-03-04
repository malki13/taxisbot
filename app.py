from flask import Flask, request, Response, jsonify
from decouple import config
import base64
import hashlib
import hmac 
import json
import tweepy
app=Flask(__name__)

CONSUMER_KEY=config('consumer_key')
CONSUMER_SECRET=config('consumer_secret')
ACCESS_TOKEN=config('access_token')
ACCESS_TOKEN_SECRET=config('access_token_secret')

@app.route('/webhook/twitter', methods=['GET'])
def webhook_challenge():
    consumer_secret_bytes = bytes(CONSUMER_SECRET,'utf-8') 
    message = bytes(request.args.get('crc_token'),'utf-8')

    sha256_hash_digest = hmac.new(consumer_secret_bytes, message , digestmod=hashlib.sha256).digest()
    response={
        'response_token':'sha256='+base64.b64encode(sha256_hash_digest).decode('utf-8')
    }

    return json.dumps(response)

@app.route('/')
def index():
    return f"<h3>Welcome to Cat Facts!</h3>"

@app.route('/webhook/twitter_sms', methods=['GET'])
def mensaje():
    auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
    auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)
    api = tweepy.API(auth,wait_on_rate_limit=True, wait_on_rate_limit_notify=True)
    
    messages = api.list_direct_messages(count=5)
    for message in reversed(messages):
        # who is sending?  
        sender_id = message.message_create["sender_id"]
        # what is she saying?
        text = message.message_create["message_data"]["text"]
        #print(sender_id)
        print(text)
        response = {
            'dest':sender_id,
            'mensaje':text
        }
    return json.dumps(response)

def validateRequest(request):
    req_headers = request.headers
    if req_headers.has_key('x-twitter-webhooks-signature'):

        twitter_signature = req_headers['x-twitter-webhooks-signature'] 
        
        consumer_secret_bytes = bytes(CONSUMER_SECRET,'utf-8') 
        payload_body = bytes(request.get_data(as_text=True),'utf-8')

        sha_256_digest = hmac.new(consumer_secret_bytes, payload_body , digestmod=hashlib.sha256).digest()

        consumer_payload_hash = "sha256="+base64.b64encode(sha_256_digest).decode('utf-8')

        if hmac.compare_digest(consumer_payload_hash,twitter_signature):
            return True
        else:
            return False

@app.route('/webhook/twitter',methods=['POST'])
def respond_with_facts():
    if validateRequest(request):
        #Do whatever you like here!
        print("ll")
    else:
        res = {'message':"Unauthorized Access"}
        return Response(res,status=401)
        
    return {'status_code':200}



if __name__=='__main__':
    app.run(port=5000)