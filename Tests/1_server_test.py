#!/bin/python3
from utils import *


if __name__ == '__main__':
    @makeTest
    def main():
        address = 'tcp:127.0.0.1:6641'
        dbs = makeRequest(address, 'list_dbs').result

        for db in dbs:
            result = makeRequest(address, 'get_schema', [db]).result
            print(f'{db} db version = {result["version"]}')
