#Part 1 Create a blockchain! 
#module 2 add cryptoCurrency
from typing import ChainMap
import uuid
import bcrypt
import datetime
from enum import unique
import hashlib
import json
from os import error
import requests 
from flask import Flask, jsonify, request,render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from  uuid import uuid4
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.wrappers import response
from iteration_utilities import unique_everseen

class Blockchain:
     def __init__(self):
         self.chain = []
         self.transactions =[]
         #genesis block is below
         self.unconf=[]
         self.create_block(proof = 0, previous_hash='1' )
         self.nodes = set()
         self.uid='burn'
         self.password=str
         self.wallkey=0
         self.wallets=[(self.uid,self.wallkey)]
         self.uniq =[a_tuple[0] for a_tuple in self.wallets] 
         self.userpass=[(self.uid,self.password)]
         self.conf=[]
         


         
         
     def create_block(self, proof, previous_hash):
         
         block={'index': len(self.chain) + 1,
                'timestamp': str(datetime.datetime.now()),
                'proof': proof,
                'transactions' : self.transactions,
                'previous_hash':previous_hash}
         #somecodee
         
         
         self.transactions = []
         self.chain.append(block)
         return block
         
     def get_previous_block(self):
         return self.chain[-1]
     
     
     def total_trans(self):
        balance = 0.0
        for i in self.chain:
            for x in i['transactions']:
                balance += x['amount']    
        return balance
        
     def check_utxo(self,id):
        recived = 0.0
        sent=0.0
        utxo=0.0
        for i in self.chain:
            for x in i['transactions']:
                if x['reciver'] == id :
                    recived += x['amount'] 
                    
            for y in i['transactions']:
                if y['sender'] == id :
                    sent += y['amount']
        utxo = recived - sent        
        return utxo
        
        
     def proof_of_work(self, previous_proof):
         new_proof = 1 
         #check if proof is new proof 
         check_proof = False
         while check_proof is False:
             hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
             if hash_operation[:4] == '0000' :
                  check_proof = True
                  
             else :
                 new_proof += 1
                  
         return new_proof
      
     def hash(self, block):
         encoded_block = json.dumps(block, sort_keys=True).encode()
         return hashlib.sha256(encoded_block).hexdigest()
     
     def is_chain_valid(self, chain):
         previous_block = chain[0]
         block_index = 1
         while   block_index <len(chain):
             block = chain[block_index]
             if block['previous_hash'] != self.hash(previous_block):
                 return False
             previous_proof = previous_block['proof']
             proof = block['proof']
             hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
             if hash_operation[:4] != '0000' :
                 return False
             previous_block = block 
             block_index += 1 
         return True

     def create_wallet(self,id):
         
         wallKey= hashlib.sha256((id.lower()).encode()).hexdigest()
         self.wallets.append((id.lower(),wallKey))
         self.uniq.append(id.lower())
         new_wall=(id.lower(),wallKey)
         return new_wall
    

     def add_transaction(self, sender, receiver, amount,):
    
         self.transactions.append({'sender': sender,                                  
                                   'reciver': receiver,
                                   'amount' : amount,
                                   'uuid':uuid.uuid4().hex})
         self.unconf+=self.transactions
         self.unconf=list(unique_everseen(self.unconf))
         previous_block = self.get_previous_block()
         return previous_block['index'] + 1
     
     def add_node(self, address):
         parsed_url = urlparse(address)
         self.nodes.add(parsed_url.netloc)
         
     def replace_chain(self) : 
         
         network = self.nodes
         longest_chain = None
         max_length= len(self.chain)
         
         for node in network:
                response = requests.get(f'http://{node}/get_chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.is_chain_valid(chain):
                        max_length =length
                        longest_chain = chain
         if longest_chain :
             self.chain = longest_chain 
             return True
         return False
     
     def syncts(self):
         network=self.nodes
         for node in network:
                otherts = requests.get(f'http://{node}/tspool')
                response= otherts.json()
                self.transactions+=response
                self.transactions=list(unique_everseen(self.transactions))
                
         return response
     
     def tconf(self):
         self.unconf += self.transactions
         self.unconf = list(unique_everseen(self.unconf))
         
         self.transactions =[]
         

         
     def confiramtor(self):
         confpool=[]
         #self.replace_chain()
         for z in self.chain:
             self.conf += [elem1['uuid'] for elem1 in z['transactions']]
             self.conf = list(unique_everseen(self.conf))
                  
         confpool += [elem2['uuid'] for elem2 in self.unconf if elem2['uuid'] not in self.conf]
         
         confpool = list(unique_everseen(confpool))
         
         return(self.conf,confpool)
             
     def unconfclean(self):
         self.unconf=[]
         
      
         
     def create_bcrypt_hash(self,password,id):
         
         # convert the string to bytes 
         password_bytes = password.encode()      
         # generate a salt
         salt = bcrypt.gensalt(14)               
         # calculate a hash as bytes
         password_hash_bytes = bcrypt.hashpw(password_bytes, salt)   
         # decode bytes to a stringss
         password_hash_str = password_hash_bytes.decode()   
         
         self.userpass.append((id,password_hash_str)) 
    
          # the password hash string should similar to:
        # $2b$10$//DXiVVE59p7G5k/4Klx/ezF7BI42QZKmoOD0NDvUuqxRE5bFFBLy
                 
        # this will return true if the user supplied a valid password and 
        # should be logged in, otherwise false
     def verify_password(self,id,password):
         try: 
          hash_from_database = [up[1] for up in self.userpass if id in up[0]]
        
          password_bytes = password.encode()
          hash_bytes = hash_from_database[0].encode()
          # this will automatically retrieve the salt from the hash, 
          # then combine it with the password (parameter 1)
          # and then hash that, and compare it to the user's hash
          does_match = bcrypt.checkpw(password_bytes, hash_bytes)
          return does_match
         except IndexError : print("exception! the id is not available!")
         

         
         

class wallForm(FlaskForm):
    wallid = StringField('Your permanet uniq id in the network', validators=[DataRequired()])
    password = StringField('Please insert your permanet password?', validators=[DataRequired()])
    passRe= StringField('Re-type your pernmanet password?', validators=[DataRequired()])
    submit = SubmitField('Submit')   
    
class transform(FlaskForm):
    wallid = StringField('Your unique id in the network', validators=[DataRequired()])
    password = StringField('Please insert your password!', validators=[DataRequired()])
    receiver= StringField('please insert the reciver idm', validators=[DataRequired()])
    
class utxo(FlaskForm):
     wallid = StringField('Your unique id in the network', validators=[DataRequired()])
     password = StringField('Please insert your password!', validators=[DataRequired()])
    
    
    
        
# part 2 - Minig our blockchain
# creating WebApp using Flask : 
    

        
 

def autoMiner():
    blockchain.replace_chain()
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    
    transactions = blockchain.add_transaction(sender = node_address,
                                              receiver='Miner', 
                                              amount = 100)
    
    previous_hash = blockchain.hash(previous_block)
    blockchain.create_block(proof, previous_hash)
    
    

def autoNodeCheck():
    blockchain.replace_chain()
    
    
def autoTransact():
    blockchain.add_transaction("hoomehr",
                               "nahal",
                                420)
    
    blockchain.add_transaction("nahal",
                               "amme",
                               71)
    
    blockchain.add_transaction("amme","hoomehr",20)

    
    

#sched = BackgroundScheduler(daemon=True)
#sched.add_job(autoMiner,'interval',seconds=120,max_instances=10000)
#sched.add_job(autoNodeCheck,'interval',seconds=120,max_instances=100)
#sched.add_job(autoTransact,'interval',seconds=10,max_instances=10000)
#sched.start()

#app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
#address of node in port 5000


# creating blockchain from the class 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'C2HWGVoMGfNTBsrYQg8EcMrdTimkZfAb'
Bootstrap(app)
node_address = str(uuid4()).replace('-', '')
blockchain = Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    #blockchain.replace_chain()
    #blockchain.syncts()
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    
    transactions = blockchain.add_transaction(sender = node_address,
                                              receiver='Miner', 
                                              amount = 100)
    
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Congrats, You just mined a block!',
                'index':block['index'],
                'time':block['timestamp'],
                'proof':block['proof'],
                'transactions' : block['transactions'],
                'previous_hash' : block['previous_hash']}
    
    return jsonify(response), 200

#get chain

@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    
    return jsonify(response), 200

#check the block chain if it's valid


@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid((blockchain.chain))
    if is_valid : 
        response ={'message':'all good the block chain is valid'}
    else:
        response={'message' : 'no that valid heh'}
    return jsonify(response), 200

#adding new transaction 

@app.route('/transact', methods=['POST'])
def transaction():
    json = request.get_json()
    transaction_keys=['sender','password','receiver','amount']
    if not all(key in json for key in transaction_keys):
        return 'some elements are missing' , 400
    elif blockchain.check_utxo(json['sender']) < json['amount'] and json['sender'] != 'hoomehr':
        return 'The amount is more than your balance'
    elif blockchain.verify_password(json['sender'],json['password']) :
        
     #which block ? with index!
     index = blockchain.add_transaction(json['sender'],
                                      json['receiver'],
                                       json['amount'])
     response = {'message': f'This transaction will be added to block {index}'}
     return jsonify(response) , 201
    else :
     return "you entered a wrong password! or even id!"
 
 #create a user with pass!
@app.route('/new_user', methods=['POST'])
def add_wallet_pass():
    json=request.get_json()
    id = json.get('id')
    inpassword = json.get('password')
    
    if id is None:
        return "no id!" , 400
    elif id.lower() in blockchain.uniq :
        return "Eror! The id is currently in use , please use another one"
    else:
        blockchain.create_wallet(id)
        blockchain.create_bcrypt_hash(inpassword,id)
        
    
    response={'message':'this is your wallet address for ever in this network! write it down and keep it safe!' ,
    'list of wallets' : str(blockchain.wallets) ,
    'blockchain-uniqs' : str(blockchain.uniq),
    'pass' : str(blockchain.userpass)}
    

    return jsonify(response),201
    


 #connecting new node
@app.route('/connect_node', methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "no node" , 400
    for node in nodes:
        blockchain.add_node(node)
    response={'message':'all the nodes are now connected',
              'total_nodes': list(blockchain.nodes)}
     
    return jsonify(response) , 201
 
#replace the chain , longest if needed

@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_valid = blockchain.replace_chain()
    if is_chain_valid : 
        response={'message':'the nodes had different chain , it\'s replaced by larger oner',
                 'new chain': blockchain.chain }
    else:
        response={'message' : 'good , the chain is the largest',
                  'current chain': blockchain.chain}
    return jsonify(response), 200


@app.route('/test', methods=['GET'])
def print_some():
    bal = blockchain.total_trans()
    return str(bal), 200 
    
@app.route('/utxo', methods=['POST'])
def utxo():
    json = request.get_json()
    id = json.get('id')
    if id is None:
        return "empty id" , 400
    else :
       utxo = blockchain.check_utxo(id)
          
    return str(utxo), 200

@app.route('/tspool', methods=['GET'])
def share_poo():
    response = blockchain.transactions
    blockchain.tconf()
    
    return jsonify(response)


@app.route('/sync', methods=['GET'])
def sync():
    x = blockchain.syncts()
    
    return str(x)

@app.route('/confirm', methods=['GET'])
def conf():
    x=blockchain.confiramtor()
    
    return jsonify(x)

@app.route('/walletform', methods=['GET', 'POST'])
def index():

    # you must tell the variable 'form' what you named the class, above
    # 'form' is the variable name used in this template: index.html
    newwallform = wallForm()
    message = ""
    walletkey=""
    inputid=""
    if newwallform.validate_on_submit():
        inputid = newwallform.wallid.data
        inputpass=newwallform.password.data
        inputRepass=newwallform.passRe.data
        if inputid.lower() in blockchain.uniq:
            # empty the form field
            message = "this id is already avaible in network, please chose a another one"
        elif inputpass!=inputRepass :
            "Your Password does not match the reType!"  
            # redirect the browser to another route and template
            #return redirect( url_for('actor', id=id) )
        else:
            blockchain.create_wallet(inputid)
            blockchain.create_bcrypt_hash(inputpass,inputid) 
            message = 'this is your wallet address for ever in this network! write it down and keep it safe!'
            walletkey = dict(blockchain.wallets)[inputid]
            
    return render_template('index.html', form=newwallform,message=message,wallkey=walletkey,id=inputid)

