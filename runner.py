from app import webapi, SockIO

if __name__ == '__main__':
    SockIO.run(webapi, debug=True, host='0.0.0.0', port=5000)