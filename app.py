#
import os

#
from dotenv import load_dotenv
from sqlalchemy import create_engine
from flask import Flask, jsonify, request, render_template
from oaiv.core.account import InteractionFunctionality
from oaiv.tools.utils import format_provider, format_w3


from logginger import Logging as logg


from hub import Hub
from logginer import logg
import pandas

load_dotenv()

ETHEREUM_NETWORK = os.getenv('ETHEREUM_NETWORK')
INFURA_PROJECT_ID = os.getenv('INFURA_PROJECT_ID')
ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
ETHPLORER_API_KEY = os.getenv('ETHPLORER_API_KEY')
DB_USER = os.getenv('DB_USER')
DB_PW = os.getenv('DB_PW')
DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
LOG_USER = os.getenv('LOG_USER')
LOG_PW = os.getenv('LOG_PW')
LOG_HOST = os.getenv('LOG_HOST')
LOG_NAME = os.getenv('LOG_NAME')
LOG_TABLE = os.getenv('LOG_TABLE')
MEDIA_STORAGE = os.getenv('MEDIA_STORAGE')

provider = format_provider(ethereum_network=ETHEREUM_NETWORK,
                           infura_project_id=INFURA_PROJECT_ID)
w3 = format_w3(provider)

ethereum_kwg = {'etherscan_api_key': ETHERSCAN_API_KEY,
                'ethereum_network': ETHEREUM_NETWORK,
                'infura_project_id': INFURA_PROJECT_ID,
                'ethplorer_api_key': ETHPLORER_API_KEY}
bitcoin_kwg = {}

ba = InteractionFunctionality(ethereum_kwg=ethereum_kwg, bitcoin_kwg=bitcoin_kwg)

conn = create_engine("postgresql+psycopg2://{0}:{1}@{2}/{3}".format(
    DB_USER, DB_PW, DB_HOST, DB_NAME
)).connect()

conn_log = create_engine("postgresql+psycopg2://{0}:{1}@{2}/{3}".format(
    LOG_USER, LOG_PW, LOG_HOST, LOG_NAME
)).connect()



logg = logg(conn_log=conn_log, log_table=LOG_TABLE)
banking = Hub(conn=conn, conn_log=conn_log, log_table=LOG_TABLE, w3=w3, ba=ba, media_storage=MEDIA_STORAGE)


#
app = Flask(__name__)

# waitress-serve --listen=localhost:8000 app:app


@app.route('/has_identity', methods=['GET'])
def has_identity():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='has_identity')
    requested = request.get_json()
    resulted = banking.has_identity(call_id=call_id, username=requested['username'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='has_identity')


    return response


@app.route('/create_identity', methods=['GET'])
def create_identity():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='create_identity')
    requested = request.get_json()
    resulted = banking.create_identity(call_id=call_id, username=requested['username'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='create_identity')
    return response


@app.route('/signin', methods=['GET'])
def signin():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='signin')
    requested = request.get_json()
    resulted = banking.signin(call_id=call_id, username=requested['username'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='signin')
    return response


@app.route('/create_account', methods=['GET'])
def create_account():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='create_account')
    requested = request.get_json()
    resulted = banking.create_account(call_id=call_id, username=requested['username'], token=requested['token'],
                                      account_blockchain=requested['account_blockchain'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='create_account')
    return response


@app.route('/add_account', methods=['GET'])
def add_account():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='add_account')
    requested = request.get_json()
    resulted = banking.add_account(call_id=call_id,
                                   username=requested['username'], token=requested['token'],
                                   account_address=requested['account_address'],
                                   account_blockchain=requested['account_blockchain'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='add_account')
    return response


@app.route('/remove_account', methods=['GET'])
def remove_account():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='remove_account')
    requested = request.get_json()
    resulted = banking.remove_account(call_id=call_id,
                                      username=requested['username'], token=requested['token'],
                                      account_id=requested['account_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='remove_account')
    return response


@app.route('/get_account_info', methods=['GET'])
def get_account_info():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='get_account_info')
    requested = request.get_json()
    resulted = banking.get_account_info(call_id=call_id, username=requested['username'], token=requested['token'],
                                        account_id=requested['account_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='get_account_info')
    return response


@app.route('/get_accounts_info', methods=['GET'])
def get_accounts_info():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='get_accounts_info')
    requested = request.get_json()
    resulted = banking.get_accounts_info(call_id=call_id, username=requested['username'], token=requested['token'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='get_accounts_info')
    return response


@app.route('/get_transactions_info', methods=['GET'])
def get_transactions_info():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='get_transactions_info')
    requested = request.get_json()
    resulted = banking.get_transactions_info(call_id=call_id,
                                             username=requested['username'], token=requested['token'],
                                             account_id=requested['account_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='get_transactions_info')
    return response


@app.route('/do_transaction', methods=['GET'])
def do_transaction():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='do_transaction')
    requested = request.get_json()
    kwargs = {x: requested[x] for x in requested.keys() if x not in [
        'username', 'token', 'sender_account_blockchain_address', 'sender_private_key', 'account_blockchain',
        'receiver_account_blockchain_address', 'value'
    ]}
    resulted = banking.do_transaction(call_id=call_id,
                                      username=requested['username'], token=requested['token'],
                                      sender_account_blockchain_address=requested['sender_account_blockchain_address'],
                                      sender_private_key=requested['sender_private_key'],
                                      account_blockchain=requested['account_blockchain'],
                                      receiver_account_blockchain_address=
                                      requested['receiver_account_blockchain_address'],
                                      value=float(requested['value']),
                                      w3=w3, **kwargs)
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='do_transaction')
    return response


@app.route('/dealer_check_exists', methods=['GET'])
def dealer_check_exists():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='dealer_check_exists')
    requested = request.get_json()
    resulted = banking.dealer_check_exists(call_id=call_id,
                                           user_id=requested['user_id'], client_token=requested['client_token'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='dealer_check_exists')
    return response


@app.route('/dealer_create_identity', methods=['POST'])
def dealer_create_identity():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='dealer_create_identity')
    requested = request.get_json()
    resulted = banking.dealer_create_identity(call_id=call_id,
                                              user_id=requested['user_id'], client_token=requested['client_token'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='dealer_create_identity')
    return response


@app.route('/dealer_get_request_info', methods=['GET'])
def dealer_get_request_info():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='dealer_get_request_info')
    requested = request.get_json()
    resulted = banking.dealer_get_request_info(call_id=call_id,
                                               user_id=requested['user_id'],
                                               client_token=requested['client_token'],
                                               message_id=requested['message_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='dealer_get_request_info')
    return response


@app.route('/dealer_get_best_quote', methods=['GET'])
def dealer_get_best_quote():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='dealer_get_best_quote')
    requested = request.get_json()
    resulted = banking.dealer_get_best_quote(call_id=call_id,
                                             user_id=requested['user_id'],
                                             token=requested['token'],
                                             request_id=requested['request_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='dealer_get_best_quote')
    return response


@app.route('/dealer_check_executed', methods=['GET'])
def dealer_check_executed():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='dealer_check_executed')
    requested = request.get_json()
    resulted = banking.dealer_check_executed(call_id=call_id,
                                             user_id=requested['user_id'],
                                             token=requested['token'],
                                             communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='dealer_check_executed')
    return response


@app.route('/dealer_list_by_request_status', methods=['GET'])
def dealer_list_by_request_status():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='dealer_list_by_request_status')
    requested = request.get_json()
    resulted = banking.dealer_list_by_request_status(call_id=call_id,
                                                     client_token=requested['client_token'],
                                                     request_id=requested['request_id'],
                                                     action=requested['action'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='dealer_list_by_request_status')
    return response


@app.route('/communication_register_reply', methods=['POST'])
def communication_register_reply():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='communication_register_reply')
    requested = request.get_json()
    resulted = banking.communication_register_reply(call_id=call_id,
                                                    user_id=requested['user_id'],
                                                    client_token=requested['client_token'],
                                                    side=requested['side'],
                                                    request_id=requested['request_id'],
                                                    message_id=requested['message_id'],
                                                    action=requested['action'],
                                                    communication_id=requested['communication_id'],
                                                    media=requested['media'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='communication_register_reply')
    return response


@app.route('/communication_check_transaction_status', methods=['GET'])
def communication_check_transaction_status():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='communication_check_transaction_status')
    requested = request.get_json()
    resulted = banking.communication_check_transaction_status(call_id=call_id,
                                                              user_id=requested['user_id'],
                                                              client_token=requested['client_token'],
                                                              side=requested['side'],
                                                              communication_id=requested['communication_id'],
                                                              tx_hash=requested['tx_hash'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='communication_check_transaction_status')
    return response


@app.route('/request_info_create', methods=['POST'])
def request_info_create():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_create')
    requested = request.get_json()
    resulted = banking.request_info_create(call_id=call_id,
                                           buyer=requested['buyer'],
                                           seller=requested['seller'],
                                           client_token=requested['client_token'],
                                           request_id=requested['request_id'],
                                           blockchain=requested['blockchain'],
                                           blockchain_address=requested['blockchain_address'],
                                           blockchain_currency=requested['blockchain_currency'],
                                           blockchain_amount=requested['blockchain_amount'],
                                           request_additional_info=requested['request_additional_info'],
                                           communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_start(call_id=call_id, group='back', method='request_info_create')
    return response


@app.route('/request_info_confirm', methods=['POST'])
def request_info_confirm():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_confirm')
    requested = request.get_json()
    resulted = banking.request_info_confirm(call_id=call_id,
                                            user_id=requested['user_id'],
                                            client_token=requested['client_token'],
                                            side=requested['side'],
                                            request_id=requested['request_id'],
                                            communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='request_info_confirm')
    return response


@app.route('/request_info_reject', methods=['POST'])
def request_info_reject():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_reject')
    requested = request.get_json()
    resulted = banking.request_info_reject(call_id=call_id,
                                           user_id=requested['user_id'],
                                           client_token=requested['client_token'],
                                           side=requested['side'],
                                           communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='request_info_reject')
    return response


@app.route('/request_info_done', methods=['POST'])
def request_info_done():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_done')
    requested = request.get_json()
    resulted = banking.request_info_done(call_id=call_id,
                                         user_id=requested['user_id'],
                                         client_token=requested['client_token'],
                                         side=requested['side'],
                                         request_id=requested['request_id'],
                                         communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='request_info_done')
    return response


@app.route('/request_info_set_quote', methods=['POST'])
def request_info_set_quote():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_set_quote')
    requested = request.get_json()
    resulted = banking.request_info_set_quote(call_id=call_id,
                                              user_id=requested['user_id'],
                                              client_token=requested['client_token'],
                                              payment_amount=requested['payment_amount'],
                                              payment_details=requested['payment_details'],
                                              communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='request_info_set_quote')
    return response


@app.route('/request_info_disputed', methods=['POST'])
def request_info_disputed():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_disputed')
    requested = request.get_json()
    resulted = banking.request_info_disputed(call_id=call_id,
                                             user_id=requested['user_id'],
                                             client_token=requested['client_token'],
                                             side=requested['side'],
                                             request_id=requested['request_id'],
                                             communication_id=requested['communication_id'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='request_info_disputed')
    return response


@app.route('/request_info_paid', methods=['POST'])
def request_info_paid():
    call_id = logg.new_call()
    logg.log_start(call_id=call_id, group='back', method='request_info_paid')
    requested = request.get_json()
    resulted = banking.request_info_paid(call_id=call_id,
                                         user_id=requested['user_id'],
                                         side=requested['side'],
                                         client_token=requested['client_token'],
                                         request_id=requested['request_id'],
                                         communication_id=requested['communication_id'],
                                         tx_hash=requested['tx_hash'])
    response = jsonify(resulted)
    logg.log_end(call_id=call_id, group='back', method='request_info_paid')
    return response
