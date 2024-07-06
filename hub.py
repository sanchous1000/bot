
import random
import hashlib
import datetime


import pytz
import bcrypt
import numpy
import pandas
from uuid import uuid4
from sqlalchemy import text
from oaiv.core.account import Actor
from oaiv.constants import blockchain_type, BlockchainType
from banking_fiat_auction_shared.constants import StatusCodes, ActionCodes, SideCodes, action_code_revert, status_code_convert, action_code_convert, side_code_convert


from banking_api_shared.constants import BackExceptionMessage
from logginer import Logging as logg





REGISTERED_CLIENTS = [''] #add token


class SafePw:
    @staticmethod
    def get_hashed_pw(plain_text_pw):
        return bcrypt.hashpw(plain_text_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    @staticmethod
    def check_pw(plain_text_password, hashed_password):
        return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


class FastPw:
    @staticmethod
    def get_hashed_pw(plain_text_pw):
        return hashlib.sha256(plain_text_pw.encode('utf-8')).hexdigest()
    @staticmethod
    def check_pw(plain_text_password, hashed_password):
        return FastPw.get_hashed_pw(plain_text_pw=plain_text_password) == hashed_password


class Status:
    @staticmethod
    def send_ok(data=None, message=None):
        result = {'status': 'OK'}
        if data is not None:
            result['data'] = data
        if message is not None:
            result['message'] = message
        return result
    @staticmethod
    def send_nok(message, e=None):
        if not e:
            return {'status': 'NOK', 'message': message}
        else:
            return {'status': 'NOK', 'message': message, 'e': e}





class Hub:
    def __init__(self, conn, conn_log, log_table, w3, ba, media_storage):
        self.conn = conn
        self.w3 = w3
        self.ba = ba
        self.logg = logg(conn_log=conn_log, log_table=log_table)
        self.media_storage = media_storage
    def _create_token(self, call_id, username):
        self.logg.log_start(call_id=call_id, group='back', method='create_token')
        current_timestamp = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).isoformat()
       
        token = str(uuid4())
        token_hashed = FastPw.get_hashed_pw(plain_text_pw=token)
        query = """
        INSERT INTO tokens (username, token, "timestamp")
        VALUES ('{0}', '{1}', '{2}')
        ;
        """.format(username, token_hashed, current_timestamp)
        self.logg.log_start(call_id=call_id, group='db', method='add_token')
        self.conn.execute(text(query))
        self.logg.log_end(call_id=call_id, group='db', method='add_token')
        self.logg.log_end(call_id=call_id, group='back', method='create_token')
        return token
    def _check_token(self, call_id, username, token):
        self.logg.log_start(call_id=call_id, group='back', method='check_token')
       
        query = """
        SELECT token
        FROM tokens
        WHERE username = '{0}'
        ;
        """.format(username)
        self.logg.log_start(call_id=call_id, group='db', method='search_for_username_tokens')
        result = pandas.read_sql(sql=text(query), con=self.conn)
        self.logg.log_end(call_id=call_id, group='db', method='search_for_username_tokens')
        if result.shape[0] == 0:
            self.logg.log_end(call_id=call_id, group='back', method='check_token')
            return False
        else:
            def check_tokens(x, token_entered):
                return FastPw.check_pw(plain_text_password=token_entered, hashed_password=x)
            result['checked'] = result['token'].apply(func=check_tokens, args=(token,))
            checked = result['checked'].any()
            self.logg.log_end(call_id=call_id, group='back', method='check_token')
            return checked
    def _check_dealer_token(self, call_id, token):
        self.logg.log_start(call_id=call_id, group='back', method='check_dealer_token')
        checked = any([x == token for x in REGISTERED_CLIENTS])
        self.logg.log_end(call_id=call_id, group='back', method='check_token')
        return checked
    def _format_address(self, account_blockchain, account_blockchain_address):
        if blockchain_type(account_blockchain) == BlockchainType.ETHEREUM:
            return self.w3.toChecksumAddress(value=account_blockchain_address)
        elif blockchain_type(account_blockchain) == BlockchainType.BITCOIN:
            if self.ba.is_address(address=account_blockchain_address, blockchain=blockchain_type(account_blockchain)):
                return account_blockchain_address
            else:
                raise ValueError("The entered address '{0}' is not a valid Bitcoin address".format(
                    account_blockchain_address))
        else:
            raise NotImplementedError("Only 'BITCOIN' and 'ETHEREUM' blockchains are currently supported")
    def _save_media(self, media, name):
        if media is None:
            return None
        else:
            p = "{0}{1}.png".format(self.media_storage, name)
            with open(p, 'wb') as media_file:
                media_file.write(media)
            return p
    def _get_reject_status(self, last_sell_side_action, last_buy_side_action):
        if (action_code_revert(last_sell_side_action) == ActionCodes.REJECT_QUOTING) and \
           (action_code_revert(last_buy_side_action) == ActionCodes.BID):
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.QUOTE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.FORCE_REJECT_QUOTE):
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.NONE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.FORCE_REJECT_QUOTE):
            return status_code_convert(StatusCodes.CLOSE)
        elif action_code_revert(last_buy_side_action) == ActionCodes.FORCE_REJECT_QUOTE:
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.QUOTE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.REJECT_NO_QUOTES):
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.NONE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.REJECT_NO_QUOTES):
            return status_code_convert(StatusCodes.CLOSE)
        elif action_code_revert(last_buy_side_action) == ActionCodes.REJECT_NO_QUOTES:
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.QUOTE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.REJECT_ONE_SELECTED):
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.NONE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.REJECT_ONE_SELECTED):
            return status_code_convert(StatusCodes.CLOSE)
        elif action_code_revert(last_buy_side_action) == ActionCodes.REJECT_ONE_SELECTED:
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.QUOTE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.REJECT_PAYMENT):
            return status_code_convert(StatusCodes.CLOSE)
        elif action_code_revert(last_buy_side_action) == ActionCodes.REJECT_PAYMENT:
            return status_code_convert(StatusCodes.CLOSE)
        elif (action_code_revert(last_sell_side_action) == ActionCodes.QUOTE) and \
             (action_code_revert(last_buy_side_action) == ActionCodes.REJECT_QUOTE):
            return status_code_convert(StatusCodes.CLOSE)
        elif action_code_revert(last_buy_side_action) == ActionCodes.REJECT_QUOTE:
            return status_code_convert(StatusCodes.CLOSE)
        return StatusCodes.CLOSE
    def _get_done_status(self, last_sell_side_action, last_buy_side_action):
        if (action_code_revert(last_sell_side_action) == ActionCodes.EXECUTE) and \
           (action_code_revert(last_buy_side_action) == ActionCodes.CONFIRM):
            return status_code_convert(StatusCodes.DONE)
        return StatusCodes.DONE
    def _get_dispute_status(self, last_sell_side_action, last_buy_side_action):
        if (action_code_revert(last_sell_side_action) == ActionCodes.EXECUTE_FAILED_SECOND) and \
           (action_code_revert(last_buy_side_action) == ActionCodes.CONFIRM):
            return status_code_convert(StatusCodes.DISPUTE)
        elif action_code_revert(last_sell_side_action) == ActionCodes.EXECUTE_FAILED_SECOND:
            return status_code_convert(StatusCodes.DISPUTE)
        return StatusCodes.DISPUTE
    def has_identity(self, call_id, username):
        try:
            query = """
            SELECT username
            FROM identities
            WHERE username = '{0}'
            ;
            """.format(username)
            self.logg.log_start(call_id=call_id, group='db', method='search_for_username_identity')
            result = pandas.read_sql(sql=text(query), con=self.conn)
            self.logg.log_end(call_id=call_id, group='db', method='search_for_username_identity')
            if result.shape[0] == 0:
                return Status.send_ok(data={'found': False})
            else:
                return Status.send_ok(data={'found': True})
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))

    def create_identity(self, call_id, username):
        try:
            query = """
            SELECT username
            FROM identities
            WHERE username = '{0}'
            ;
            """.format(username)
            self.logg.log_start(call_id=call_id, group='db', method='search_for_username_identity')
            result = pandas.read_sql(sql=text(query), con=self.conn)
            self.logg.log_end(call_id=call_id, group='db', method='search_for_username_identity')
            if result.shape[0] == 0:
                query = """
                INSERT INTO identities (username, user_pw)
                VALUES ('{0}', '{1}')
                ;
                """.format(username, 'NO_PASSWORD')
                self.logg.log_start(call_id=call_id, group='db', method='add_identity')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='add_identity')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.USERNAME_ALREADY_EXISTS)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))

    def signin(self, call_id, username):
        try:
            # TODO: check safety issues
            query = """
            SELECT username
            FROM identities
            WHERE username = '{0}'
            ;
            """.format(username)
            self.logg.log_start(call_id=call_id, group='db', method='search_for_username_identity')
            result = pandas.read_sql(sql=text(query), con=self.conn)
            self.logg.log_end(call_id=call_id, group='db', method='search_for_username_identity')
            if result.shape[0] == 1:
                username = result['username'].values[0]
                token = self._create_token(call_id=call_id, username=username)
                return Status.send_ok(data={'token': token})
            else:
                return Status.send_nok(message=BackExceptionMessage.USERNAME_DOES_NOT_EXIST)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def create_account(self, call_id, username, token, account_blockchain):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                found = False
                while not found:
                    account_id = '{0}'.format(random.randrange(start=0, stop=10**10)).zfill(10)
                    query = """
                    SELECT account_id
                    FROM accounts
                    WHERE account_id = '{0}'
                    ;
                    """.format(account_id)
                    self.logg.log_start(call_id=call_id, group='db', method='search_for_account')
                    result = pandas.read_sql(sql=text(query), con=self.conn)
                    self.logg.log_end(call_id=call_id, group='db', method='search_for_account')
                    if result.shape[0] == 0:
                        found = True
                self.logg.log_start(call_id=call_id, group='blockchain', method='create_account')
                actor = self.ba.create_account(blockchain=blockchain_type(account_blockchain))
                self.logg.log_end(call_id=call_id, group='blockchain', method='create_account')
                query = """
                INSERT INTO accounts (username, account_id, account_blockchain, account_blockchain_address, currency)
                VALUES ('{0}', '{1}', '{2}', '{3}', ';')
                ;
                """.format(username, account_id, account_blockchain, actor.address)
                self.logg.log_start(call_id=call_id, group='db', method='add_account')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='add_account')
                return Status.send_ok(data={'address': actor.address, 'private_key': actor.private_key})
            else:
                return Status.send_nok(message='The token provided is invalid')
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def add_account(self, call_id, username, token, account_address, account_blockchain):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                account_address = self._format_address(account_blockchain=account_blockchain,
                                                       account_blockchain_address=account_address)
                query = """
                SELECT account_id
                FROM accounts
                WHERE username = '{0}' AND account_blockchain = '{1}' AND account_blockchain_address = '{2}'
                ;
                """.format(username, account_blockchain, account_address)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_account_blockchain')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_account_blockchain')
                if result.shape[0] == 0:
                    found = False
                    while not found:
                        account_id = '{0}'.format(random.randrange(start=0, stop=10 ** 10)).zfill(10)
                        query = """
                        SELECT account_id
                        FROM accounts
                        WHERE account_id = '{0}'
                        ;
                        """.format(account_id)
                        self.logg.log_start(call_id=call_id, group='db', method='search_for_account')

                        result = pandas.read_sql(sql=text(query), con=self.conn)
                        self.logg.log_end(call_id=call_id, group='db', method='search_for_account')
                        if result.shape[0] == 0:
                            found = True
                    query = """
                    INSERT INTO accounts (username, account_id, account_blockchain, account_blockchain_address, currency)
                    VALUES ('{0}', '{1}', '{2}', '{3}', ';')
                    ;
                    """.format(username, account_id, account_blockchain, account_address)
                    self.logg.log_start(call_id=call_id, group='db', method='add_account')
                    self.conn.execute(text(query))
                    self.logg.log_end(call_id=call_id, group='db', method='add_account')
                    return Status.send_ok(data={'account_id': account_id})
                else:
                    return Status.send_nok(message=BackExceptionMessage.ACCOUNT_ALREADY_EXISTS)
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def remove_account(self, call_id, username, token, account_id):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                query = """
                SELECT account_id
                FROM accounts
                WHERE username = '{0}' AND account_id = '{1}'
                ;
                """.format(username, account_id)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_account_id')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_account_id')
                if result.shape[0] == 0:
                    return Status.send_nok(message=BackExceptionMessage.ACCOUNT_DOES_NOT_EXIST)
                else:
                    query = """
                    DELETE
                    FROM accounts
                    WHERE username = '{0}' AND account_id = '{1}'
                    ;
                    """.format(username, account_id)
                    self.logg.log_start(call_id=call_id, group='db', method='remove_account')
                    self.conn.execute(text(query))
                    self.logg.log_end(call_id=call_id, group='db', method='remove_account')
                    return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def get_account_info(self, call_id, username, token, account_id):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                query = """
                SELECT account_id, account_blockchain, account_blockchain_address, currency
                FROM accounts
                WHERE username = '{0}' AND account_id = '{1}'
                ;
                """.format(username, account_id)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_account_spec_info')
                results = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_account_spec_info')

                self.logg.log_start(call_id=call_id, group='blockchain', method='account_balance')
                balance_result = self.ba.balance(addresses=[results['account_blockchain_address'].values[0]],
                                                 blockchain=blockchain_type(results['account_blockchain'].values[0]))
                self.logg.log_end(call_id=call_id, group='blockchain', method='account_balance')

                def apply_it(x):
                    return balance_result[results['account_blockchain_address'].values[0]]

                results['balance'] = results['account_blockchain_address'].apply(func=apply_it)

                return Status.send_ok(data=results.to_dict())
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def get_accounts_info(self, call_id, username, token):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                query = """
                SELECT account_id, account_blockchain, account_blockchain_address, currency
                FROM accounts
                WHERE username = '{0}'
                ;
                """.format(username)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_accounts_username')
                results = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_accounts_username')

                results['balance'] = numpy.nan

                return Status.send_ok(data=results.to_dict())
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def get_transactions_info(self, call_id, username, token, account_id):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                query = """
                SELECT account_blockchain, account_blockchain_address
                FROM accounts
                WHERE account_id = '{0}'
                ;
                """.format(account_id)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_account')
                results = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_account')
                if results.shape[0] == 0:
                    return Status.send_nok(message=BackExceptionMessage.ACCOUNT_DOES_NOT_EXIST)
                else:

                    self.logg.log_start(call_id=call_id, group='blockchain', method='account_transactions')
                    pack_0, pack_1 = self.ba.get_transactions(account=results['account_blockchain_address'].values[0],
                                                              blockchain=blockchain_type(
                                                                  results['account_blockchain'].values[0]),
                                                              sort='desc', raw=False)
                    self.logg.log_end(call_id=call_id, group='blockchain', method='account_transactions')
                    pack_0, pack_1 = pandas.DataFrame(data=pack_0), pandas.DataFrame(data=pack_1)
                    pack_0['account_blockchain'] = results['account_blockchain'].values[0]
                    pack_0['account_blockchain_address'] = results['account_blockchain_address'].values[0]
                    pack_1['account_blockchain'] = results['account_blockchain'].values[0]
                    pack_1['account_blockchain_address'] = results['account_blockchain_address'].values[0]
                    results = pandas.concat((pack_0, pack_1), axis=0, ignore_index=True)
                    results['datetime'] = results['datetime'].apply(lambda x: x.isoformat())
                    return Status.send_ok(data=results.to_dict())
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def do_transaction(self, call_id, username, token,
                       sender_account_blockchain_address, sender_private_key, account_blockchain,
                       receiver_account_blockchain_address, value, **kwargs):
        try:
            if self._check_token(call_id=call_id, username=username, token=token):
                """
                sender = Actor(blockchain=blockchain_type(account_blockchain),
                               w3=self.w3, private_key=private_key, address=None)
                receiver = Actor(blockchain=blockchain_type(account_blockchain),
                                 w3=self.w3, private_key=None, address=to_account_blockchain_address)
                """
                sender = Actor(blockchain=blockchain_type(account_blockchain),
                               private_key=sender_private_key, address=sender_account_blockchain_address, **kwargs)
                receiver = Actor(blockchain=blockchain_type(account_blockchain),
                                 private_key=None, address=receiver_account_blockchain_address, **kwargs)
                self.logg.log_start(call_id=call_id, group='blockchain', method='make_transaction')
                tx = self.ba.make_transaction(blockchain=blockchain_type(account_blockchain),
                                              sender=sender, receiver=receiver, value=value, **kwargs)
                self.logg.log_end(call_id=call_id, group='blockchain', method='make_transaction')
                return Status.send_ok(data={'tx': tx})
            else:
                return Status.send_nok(message='The token provided is invalid')
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def dealer_check_exists(self, call_id, user_id, client_token):
        try:
            if self._check_dealer_token(call_id, client_token):
                query = """
                SELECT user_id
                FROM dealer_identities
                WHERE user_id = '{0}'
                ;
                """.format(user_id)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_dealer_identity')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_dealer_identity')
                if result.shape[0] == 0:
                    return Status.send_ok(data={'found': False})
                else:
                    return Status.send_ok(data={'found': True})
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def dealer_create_identity(self, call_id, user_id, client_token):
        try:
            if self._check_dealer_token(call_id, client_token):
                query = """
                SELECT user_id
                FROM dealer_identities
                WHERE user_id = '{0}'
                ;
                """.format(user_id)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_dealer_identity')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_dealer_identity')
                if result.shape[0] == 0:
                    query = """
                    INSERT INTO dealer_identities (user_id)
                    VALUES ('{0}')
                    ;
                    """.format(user_id)
                    self.logg.log_start(call_id=call_id, group='db', method='add_dealer_identity')
                    self.conn.execute(text(query))
                    self.logg.log_end(call_id=call_id, group='db', method='add_dealer_identity')
                    return Status.send_ok()
                else:
                    return Status.send_nok(message=BackExceptionMessage.USERNAME_ALREADY_EXISTS)
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=BackExceptionMessage.NON_SPECIFIC, e=str(e))
    def dealer_get_request_info(self, call_id, user_id, client_token, message_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                query = """
                SELECT communication_id
                FROM dealer_request_communication
                WHERE user_id='{0}' AND message_id ='{1}'
                ;
                """.format(user_id, message_id)
                print(query)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_dealer_request_id_by_message_id')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_dealer_request_id_by_message_id')
                if result.shape[0] == 1:
                    communication_id = result['communication_id'].values[0]
                    query = """
                    SELECT i.request_id, i.communication_id, i.status, c.action
                    FROM 
                    (
                    SELECT request_id, communication_id, status
                    FROM dealer_request_info
                    WHERE communication_id = '{0}'
                    ) AS i
                    LEFT JOIN
                    (
                    SELECT DISTINCT ON (communication_id) communication_id, action
                    FROM dealer_request_communication
                    WHERE communication_id = '{0}'
                    ORDER BY communication_id, communication_datetime DESC
                    ) AS c
                    ON i.communication_id = c.communication_id
                    ;
                    """.format(communication_id)
                    print(query)
                    self.logg.log_start(call_id=call_id, group='db', method='construct_request_info_by_communication_id')
                    result = pandas.read_sql(sql=text(query), con=self.conn)
                    self.logg.log_end(call_id=call_id, group='db', method='construct_request_info_by_communication_id')
                    if result.shape[0] == 1:
                        request_id = result['request_id'].values[0]
                        action, status = result['action'].values[0], result['status'].values[0]
                        return Status.send_ok(data={'request_id': request_id, 'communication_id': communication_id, 'status': status, 'action': action})
                    else:
                        # TODO: this should be controlled
                        return Status.send_nok(message=None)
                else:
                    # TODO: this should be controlled
                    return Status.send_nok(message=None)
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def dealer_get_best_quote(self, call_id, user_id, token, request_id):
        try:
            if self._check_token(call_id=call_id, username=user_id, token=token):
                status = status_code_convert(StatusCodes.OPEN)
                action = action_code_convert(ActionCodes.QUOTE)
                sell_side = side_code_convert(SideCodes.SELL)
                query = """
                SELECT DISTINCT ON (q.payment_amount) q.payment_amount, 
                                                      -- (q.payment_amount / q.blockchain_amount) AS best_quote,
                                                      q.blockchain_amount,
                                                      q.action AS action,
                                                      q.communication_id AS communication_id,
                                                      q.seller_id AS best_seller,
                                                      q.payment_details
                FROM 
                (
                SELECT i.payment_amount, i.payment_details, i.blockchain_amount, i.communication_id, i.seller_id, c.action
                FROM
                (
                SELECT seller_id, payment_amount, payment_details, blockchain_amount, communication_id
                FROM dealer_request_info
                WHERE request_id = '{0}'
                AND payment_amount IS NOT NULL
                AND status = '{1}'
                ) AS i
                LEFT JOIN
                (
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE side = '{2}'
                AND action = '{3}'
                ORDER BY communication_id, communication_datetime DESC
                ) AS c
                ON i.communication_id = c.communication_id
                ) AS q
                WHERE q.action IS NOT NULL
                ORDER BY payment_amount ASC
                ;
                """.format(request_id, status, sell_side, action)
                print(query)
                self.logg.log_start(call_id=call_id, group='db', method='calculate_dealer_best_quote_by_request_id')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='calculate_dealer_best_quote_by_request_id')
                if result.shape[0] == 1:
                    action, communication_id = result['action'].values[0], result['communication_id'].values[0]
                    # best_quote, best_amount = result['best_quote'].values[0], result['payment_amount'].values[0]
                    payment_amount, blockchain_amount = result['payment_amount'].values[0], result['blockchain_amount'].values[0]
                    payment_details = result['payment_details'].values[0]
                    best_seller = result['best_seller'].values[0]
                    return Status.send_ok(data={'found': True,
                                                'best_quote': float(payment_amount) / float(blockchain_amount), 'best_amount': payment_amount,
                                                'payment_details': payment_details,
                                                'action': action, 'communication_id': communication_id,
                                                'best_seller': best_seller})
                else:
                    return Status.send_ok(data={'found': False})
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def dealer_check_executed(self, call_id, user_id, token, communication_id):
        try:
            if self._check_token(call_id=call_id, username=user_id, token=token):
                sell_side = side_code_convert(SideCodes.SELL)
                query = """
                SELECT i.communication_id, i.tx_hash, c.action
                FROM 
                (
                SELECT communication_id, tx_hash
                FROM dealer_request_info
                WHERE communication_id = '{0}'
                ) AS i
                LEFT JOIN
                (
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ) AS c
                ON i.communication_id = c.communication_id
                ;
                """.format(communication_id, sell_side)
                self.logg.log_start(call_id=call_id, group='db', method='construct_request_info_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='construct_request_info_by_communication_id_and_side')
                if result.shape[0] == 1:
                    action, tx_hash = result['action'].values[0], result['tx_hash'].values[0]
                    return Status.send_ok(
                        data={'action': action, 'tx_hash': tx_hash})
                else:
                    # TODO: this should be controlled
                    return Status.send_nok(message=None)
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def dealer_list_by_request_status(self, call_id, client_token, request_id, action):
        try:
            if self._check_dealer_token(call_id, client_token):
                query = """
                SELECT DISTINCT user_id
                FROM dealer_request_communication
                WHERE request_id = '{0}'
                AND action = '{1}'
                ;
                """.format(request_id, action)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_sellers_by_request_id_and_action')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_sellers_by_request_id_and_action')
                dealers_listed = result['user_id'].values.tolist()
                return Status.send_ok(
                    data={'dealers_listed': dealers_listed})
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def communication_register_reply(self, call_id, user_id, client_token, side, request_id, message_id, action, communication_id, media):
        try:
            if self._check_dealer_token(call_id, client_token):
                current_timestamp = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).isoformat()
                media_name = '{0}_{1}'.format(user_id, message_id)
                media_link = self._save_media(media=media, name=media_name)
                query = """
                INSERT INTO dealer_request_communication (communication_datetime, user_id, side, request_id, message_id, action, communication_id, media)
                VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}')
                ;
                """.format(current_timestamp, user_id, side, request_id, message_id, action, communication_id, media_link)
                self.logg.log_start(call_id=call_id, group='db', method='add_communication_register_reply')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='add_communication_register_reply')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def communication_check_transaction_status(self, call_id, user_id, client_token, side, communication_id, tx_hash):
        try:
            if self._check_dealer_token(call_id, client_token):
                query = """
                SELECT blockchain_account, blockchain_account_address, blockchain_amount, blockchain_currency, opened_datetime
                FROM dealer_request_info
                WHERE communication_id = '{0}'
                ;
                """.format(communication_id)
                self.logg.log_start(call_id=call_id, group='db', method='add_request_info')
                results = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='add_request_info')
                self.logg.log_start(call_id=call_id, group='blockchain', method='account_transactions')
                pack_0, pack_1 = self.ba.get_transactions(account=results['blockchain_account_address'].values[0],
                                                          blockchain=blockchain_type(
                                                              results['blockchain_account'].values[0]),
                                                          sort='desc', raw=False)
                self.logg.log_end(call_id=call_id, group='blockchain', method='account_transactions')
                pack_0, pack_1 = pandas.DataFrame(data=pack_0), pandas.DataFrame(data=pack_1)
                print(pack_0)
                print(pack_1)
                pack_0['blockchain_account'] = results['blockchain_account'].values[0]
                pack_0['blockchain_account_address'] = results['blockchain_account_address'].values[0]
                pack_1['blockchain_account'] = results['blockchain_account'].values[0]
                pack_1['blockchain_account_address'] = results['blockchain_account_address'].values[0]
                results_blockchain = pandas.concat((pack_0, pack_1), axis=0, ignore_index=True)
                results_blockchain['datetime'] = results_blockchain['datetime'].apply(lambda x: x.isoformat())
                print(results_blockchain)
                if tx_hash in results_blockchain['tx'].values:
                    ix = results_blockchain['tx'].values.tolist().index(tx_hash)
                    print(results['opened_datetime'].values[0])
                    print(results_blockchain['datetime'].values[ix])
                    # TODO: check that this conversion will not cause any issues in future
                    if (float(results_blockchain['value'].values[ix]) == float(results['blockchain_amount'].values[0])) and \
                            (results_blockchain['currency'].values[ix] == results['blockchain_currency'].values[0]) and \
                            True:
                        # TODO: the tz issue has to be fixed and this has to be implemented
                            # (results_blockchain['datetime'].values[ix] > numpy.datetime_as_string(results['opened_datetime'].values[0])):
                        result = True
                    else:
                        result = False
                else:
                    result = False
                return Status.send_ok(data={'result': result})
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_create(self, call_id, buyer, seller, client_token, request_id, blockchain, blockchain_address, blockchain_currency, blockchain_amount, request_additional_info, communication_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                # TODO: fix both the timestamps here and the timestamp in oaiv so that they will be UTC dates!
                current_timestamp = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).isoformat()
                # current_timestamp = (datetime.datetime.utcnow() + datetime.timedelta(hours=3)).replace(tzinfo=pytz.utc).isoformat()
                status = status_code_convert(StatusCodes.OPEN)
                query = """
                INSERT INTO dealer_request_info (opened_datetime, buyer_id, seller_id, request_id, status, blockchain_account, blockchain_account_address, blockchain_currency, blockchain_amount, request_additional_info, quoted_datetime, payment_amount, communication_id, tx_hash)
                VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', NULL, NULL, '{10}', NULL)
                ;
                """.format(current_timestamp, buyer, seller, request_id, status, blockchain, blockchain_address, blockchain_currency, blockchain_amount, request_additional_info, communication_id)
                print(query)
                self.logg.log_start(call_id=call_id, group='db', method='add_request_info')
                self.conn.execute(text(query))
                print('executed')
                self.logg.log_end(call_id=call_id, group='db', method='add_request_info')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_confirm(self, call_id, user_id, client_token, side, request_id, communication_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_reject(self, call_id, user_id, client_token, side, communication_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                sell_side = side_code_convert(SideCodes.SELL)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, sell_side)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_last_action_by_communication_id_and_side')
                last_sell_side_action = result['action'].values[0]
                buy_side = side_code_convert(SideCodes.BUY)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, buy_side)
                self.logg.log_start(call_id=call_id, group='db', method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db', method='search_for_last_action_by_communication_id_and_side')
                last_buy_side_action = result['action'].values[0]
                status = self._get_reject_status(last_sell_side_action=last_sell_side_action,
                                                 last_buy_side_action=last_buy_side_action)
                query = """
                UPDATE dealer_request_info
                SET status = '{0}'
                WHERE communication_id = '{1}'
                ;
                """.format(status, communication_id)
                self.logg.log_start(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_done(self, call_id, user_id, client_token, side, request_id, communication_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                sell_side = side_code_convert(SideCodes.SELL)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, sell_side)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                last_sell_side_action = result['action'].values[0]
                buy_side = side_code_convert(SideCodes.BUY)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, buy_side)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                last_buy_side_action = result['action'].values[0]
                status = self._get_done_status(last_sell_side_action=last_sell_side_action,
                                               last_buy_side_action=last_buy_side_action)
                query = """
                UPDATE dealer_request_info
                SET status = '{0}'
                WHERE communication_id = '{1}'
                ;
                """.format(status, communication_id)
                self.logg.log_start(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_set_quote(self, call_id, user_id, client_token, payment_amount, payment_details, communication_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                query = """
                UPDATE dealer_request_info
                SET payment_amount = {0}, payment_details = '{1}'
                WHERE seller_id = '{2}' AND communication_id = '{3}'
                ;
                """.format(payment_amount, payment_details, user_id, communication_id)
                self.logg.log_start(call_id=call_id, group='db', method='update_dealer_request_info_by_seller_and_communication_id')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='update_dealer_request_info_by_seller_and_communication_id')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_disputed(self, call_id, user_id, client_token, side, request_id, communication_id):
        try:
            if self._check_dealer_token(call_id, client_token):
                sell_side = side_code_convert(SideCodes.SELL)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, sell_side)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                last_sell_side_action = result['action'].values[0]
                buy_side = side_code_convert(SideCodes.BUY)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, buy_side)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                last_buy_side_action = result['action'].values[0]
                status = self._get_dispute_status(last_sell_side_action=last_sell_side_action,
                                                  last_buy_side_action=last_buy_side_action)
                query = """
                UPDATE dealer_request_info
                SET status = '{1}'
                WHERE communication_id = '{0}'
                ;
                """.format(communication_id, status_code_convert(code=status))
                self.logg.log_start(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))
    def request_info_paid(self, call_id, user_id, side, client_token, request_id, communication_id, tx_hash):
        try:
            if self._check_dealer_token(call_id, client_token):
                print('hello')
                sell_side = side_code_convert(SideCodes.SELL)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, sell_side)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                last_sell_side_action = result['action'].values[0]
                buy_side = side_code_convert(SideCodes.BUY)
                query = """
                SELECT DISTINCT ON (communication_id) communication_id, action
                FROM dealer_request_communication
                WHERE communication_id = '{0}'
                AND side = '{1}'
                ORDER BY communication_id, communication_datetime DESC
                ;
                """.format(communication_id, buy_side)
                self.logg.log_start(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                result = pandas.read_sql(sql=text(query), con=self.conn)
                self.logg.log_end(call_id=call_id, group='db',
                                 method='search_for_last_action_by_communication_id_and_side')
                last_buy_side_action = result['action'].values[0]
                status = self._get_done_status(last_sell_side_action=last_sell_side_action,
                                               last_buy_side_action=last_buy_side_action)
                print(communication_id)
                print(status)
                print(tx_hash)
                query = """
                UPDATE dealer_request_info
                SET status = '{1}', tx_hash = '{2}'
                WHERE communication_id = '{0}'
                ;
                """.format(communication_id, status_code_convert(code=status), tx_hash)
                self.logg.log_start(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                self.conn.execute(text(query))
                self.logg.log_end(call_id=call_id, group='db', method='update_dealer_request_info_by_communication_id')
                return Status.send_ok()
            else:
                return Status.send_nok(message=BackExceptionMessage.INVALID_TOKEN)
        except Exception as e:
            return Status.send_nok(message=None, e=str(e))