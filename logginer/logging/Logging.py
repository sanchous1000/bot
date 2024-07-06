import pandas
from sqlalchemy import text,create_engine
import datetime
import pytz


class Logging:
    def __init__(self, conn_log, log_table):
        self.conn_log = conn_log
        self.log_table = log_table
    def new_call(self):
        query = """
        SELECT max(call_id)
        FROM {0}
        ;
        """.format(self.log_table)
        result = pandas.read_sql(sql=text(query), con=self.conn_log).values[0][0]
        if result is None:
            return 0
        else:
            return result + 1

    


    def log_start(self, call_id, group, method):
        query = """
        INSERT INTO {0} (call_id, "group", method, "status", "timestamp")
        VALUES ({1}, '{2}', '{3}', 'start', '{4}')
        ;
        """.format(self.log_table, call_id, group, method,
                   datetime.datetime.utcnow().replace(tzinfo=pytz.utc).isoformat())
        self.conn_log.execute(text(query))

    def log_end(self, call_id, group, method):
        query = """
        INSERT INTO {0} (call_id, "group", method, "status", "timestamp")
        VALUES ({1}, '{2}', '{3}', 'end', '{4}')
        ;
        """.format(self.log_table, call_id, group, method,
                   datetime.datetime.utcnow().replace(tzinfo=pytz.utc).isoformat())
        self.conn_log.execute(text(query))

# TODO: add text file
