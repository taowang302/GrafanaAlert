from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import cgi
import json
import urllib.parse
from socketserver import ThreadingMixIn
import sys
import os
import signal
import logging
import requests
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
import configparser
import threading
# from time import sleep
import time

def config_log(config, console=False):
    level_dic = {"DEBUG": logging.DEBUG,
                 "INFO": logging.INFO,
                 "ERROR": logging.ERROR,
                 "CRITICAL": logging.CRITICAL,
                 "WARNING": logging.WARNING}
    log_level = config.get("log_level")
    log_level = level_dic.get(log_level.upper())
    # log_level = log_level.upper()
    # 创建一个logger
    logger = logging.getLogger('runlog')
    logger.setLevel(log_level)
    # 定义handler的输出格式
    formatter = logging.Formatter(
        "[%(asctime)s] [%(module)s] [%(lineno)d] %(funcName)s %(levelname)s [TD%(thread)d] %(message)s",
        datefmt='%F %T')

    # 创建一个handler，用于写入日志文件
    fh = logging.FileHandler(config.get('log_path'))
    fh.setLevel(log_level)
    fh.setFormatter(formatter)
    # 给logger添加handler
    logger.addHandler(fh)
    # 再创建一个handler，用于输出到控制台
    if console:
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(formatter)
        # 给logger添加handler
        logger.addHandler(ch)
    return logger

def config_timer():
    if len(alert_dic) > 0 :
        log.info(alert_dic)
    timer = threading.Timer(interval=30, function=config_timer)
    timer.start()

class Daemon(object):
    def __init__(self, stdin=os.devnull, stdout=os.devnull, stderr=os.devnull, home_dir='.', umask=int('022'), verbose=1):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.home_dir = home_dir
        self.verbose = verbose
        self.umask = umask
        self.daemon_alive = True

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            log.error("fork failed: {} {}".format(e.errno, e.strerror))
            sys.exit(1)
        os.chdir(self.home_dir)
        os.setsid()
        os.umask(self.umask)
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            log.error("fork failed: {} {}".format(e.errno, e.strerror))
            sys.exit(1)
        if sys.platform != 'darwin':
            sys.stdout.flush()
            sys.stderr.flush()
            si = open(self.stdin, 'r')
            so = open(self.stdout, 'ab')
            if self.stderr:
                se = open(self.stderr, 'ab', 0)
            else:
                se = so
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())

        def sigtermhandler(signum, frame):
            self.daemon_alive = False
            signal.signal(signal.SIGTERM, sigtermhandler)
            signal.signal(signal.SIGINT, sigtermhandler)

        if self.verbose >= 1:
            print("Server Started")
        pid = str(os.getpid())

    def start(self, command_list):
        if self.verbose >= 1:
            print("Starting Server...")
        self.daemonize()
        self.run(command_list)

    def is_running(self):
        pid = self.get_pid()
        print(pid)
        return pid and os.path.exists('/proc/%d' % pid)

    def run(self, command_list):
        command_list()
        # subprocess.Popen(command_list)


class TodoHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        log.info('receive request GET {}'.format(self.path))
        if self.path == '/':
            log.error('error request')
            self.send_error(404, "File not found.")
            return
        elif self.path == "/getip":
            self.send_response(200)
            response_mesg = self.client_address[0].encode(encoding="utf-8")
            self.send_header('Content-Length', len(response_mesg))
            self.end_headers()
            self.wfile.write(response_mesg)
            return
        try:
            parse_path = urllib.parse.urlparse(self.path)
            query_dic = urllib.parse.parse_qs(parse_path.query, True)
            # log.info("query_dic:".format(query_dic))
            check_status = self.check_alert_status(query_dic.get("id")[0], False)
            if 0 == check_status or 1 == check_status:
                log.info("change {} status to {}".format(query_dic.get("id")[0], query_dic.get("status")[0]))
                alert_dic[query_dic.get("id")[0]]["status"] = query_dic.get("status")[0]
        except:
            self.send_response(500)
            response_mesg = json.dumps({"status": "Fail","reseaon": sys.exc_info()[1]}).encode(encoding="utf-8")
        else:
            self.send_response(200)
            response_mesg = json.dumps({"status": "OK"}).encode(encoding="utf-8")
        finally:
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Length', len(response_mesg))
            self.end_headers()
            self.wfile.write(response_mesg)

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        log.debug("ctype:{},type:{}\npdict:{},type:{}".format(ctype, type(ctype), pdict, type(pdict)))
        if ctype == 'application/json':
            length = int(self.headers['content-length'])
            post_values = self.rfile.read(length).decode()
            post_values = json.loads(post_values)
            # log.info(post_values)
        else:
            log.error("not json data which received")
            self.send_error(415, "Only json data is supported.")
            return
        log.info("receive message from {},message digest:{}".format(str(self.client_address), post_values.get("message")))
        # 将收到的接口以json格式展示
        log.info(
                'receive:\n{}'.format(json.dumps(post_values, indent=4, sort_keys=False, ensure_ascii=False)))

        self.send_response(200)
        # log.info('response {}'.format(msg_return[1]))
        response_mesg = json.dumps({"status": "OK"}).encode(encoding="utf-8")
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Length', len(response_mesg))
        self.end_headers()
        self.wfile.write(response_mesg)
        # 将事务处理调整成异步
        self.gen_msg(post_values)
        # response_mesg = json.dumps(msg_return[1]).encode(encoding="utf-8")
        # log.info('send response:\n{}'.format(json.dumps(msg_return[1], indent=4, sort_keys=False, ensure_ascii=False)))

    def check_alert_status(self, alert_id, check_type=True):
        # log.info(alert_id)
        if alert_dic.get(alert_id):
            if alert_dic.get(alert_id).get("status") == 1:
                log.info("{} alert status:1".format(alert_id))
                return 1
            else:
                log.info("{} alert status:0".format(alert_id))
                return 0
        else:
            if check_type:
                log.info("add host:{} into alert list".format(alert_id))
                alert_dic[alert_id] = {"status": 1}
                return 1
            else:
                return 2

    def gen_msg(self, post_body):
        alert_host = post_body.get("data").get("series")[0].get("tags").get("host")
        alert_id = post_body.get("id")
        if self.check_alert_status(alert_id):
            title = alert_id
            send_msg = post_body.get("message")
            messages = {"msgtype": "text","text": {"content": ""},"at": {"atMobiles": [],"isAtAll": "false"}}
            messages["text"]["content"]=send_msg
            log.debug(post_body)
            thread1 = myThread(1, title=title,message=post_body)
            thread2 = myThread(0, title, post_body)
            # 开启线程
            thread1.start()
            log.info("start a new thread to send Email message [{}]".format(thread1.ident))
            thread2.start()
            log.info("start a new thread to send Ding message [{}]".format(thread2.ident))

class SendMessages():
    def __init__(self, config_dic):
        self.dingtalkurl = config_dic.get("DING").get("url")
        self.sender = config_dic.get("SMTP").get("sender")
        self.port = config_dic.get("SMTP").get("port")
        self.host = config_dic.get("SMTP").get("host")
        self.username = config_dic.get("SMTP").get("username")
        self.password = config_dic.get("SMTP").get("password")
        self.reveives = config_dic.get("SMTP").get("reveives")

    def send_ding(self, data):
        url = self.dingtalkurl
        # url="http://127.0.0.1:8088/"
        try:
            ret = requests.post(url, data=json.dumps(data), headers = {"Content-Type": "application/json"})
        except:
            log.error("send Ding message", sys.exc_info()[1])
            return
        else:
            log.info("send Ding message", ret.status_code, ret.text)
            return

    def send_mail(self,title, messages):
        level = messages.get("level")
        if "OK" == level:
            reason = "恢复"
            alert_dic.pop(title)
            log.info("remove {}".format(title))
        else:
            reason = "达到预警值"
        value = messages.get("data").get("series")[0].get("values")[0][1]
        alert_time = messages.get("data").get("series")[0].get("values")[0][0]
        trigger = messages.get("id").split(":")[0]
        email_message = "主机：{}\n触发原因：{}\n触发器：{}\n当前值：{}\n问题发生时间：{}\n告警发出时间：{}".format(messages.get("data").get("series")[0].get("tags").get("host"),
                                                                              reason,
                                                                              trigger,
                                                                              value,
                                                                              alert_time,
                                                                              time.strftime("%FT%TZ",time.localtime()))
        log.debug(type(self.reveives))
        receivers = (self.reveives.split(","))  # 接收邮件
        message = MIMEText(str(email_message), 'plain', 'utf-8')
        # message = MIMEText("",'plain', 'utf-8')
        log.debug(str(receivers))
        log.debug('type => {}\n message =>{}'.format(type(message), message))
        message['From'] = formataddr(["TICK Alert", self.username])
        # message['To'] = Header(",".join(receivers), 'utf-8')
        message['To'] = ",".join(receivers)
        subject = title
        message['Subject'] = Header(subject, 'utf-8')
        log.debug(message.as_string())

        try:
            smtpObj = smtplib.SMTP()
            smtpObj.connect(self.host, 25)  # 25 为 SMTP 端口号
            smtpObj.login(self.username, self.password)
            smtpObj.sendmail(self.username, receivers, message.as_string())
        except smtplib.SMTPException as e:
            log.error("Error: Send email fail", e)
            raise AttributeError(e) from e
            # log.error(e,"Error: Send email fail")
        except:
            log.error(sys.exc_info()[1])
        else:
            log.info("Send email success")
        finally:
            return

class myThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, mode, title, message):
        threading.Thread.__init__(self)
        self.mode = mode
        self.message = message
        self.title = title


    def run(self):  # 把要执行的代码写到run函数里面 线程在创建后会直接运行run函数
        if self.mode:
            try:
                time.sleep(1)
                log.info("new thread")
            except:
                log.error("send Ding failed", sys.exc_info()[1])
        else:
            try:
                log.debug(self.message)
                sendmessage.send_mail(self.title, self.message)
            except:
                log.error("send mail failed", sys.exc_info()[1])


class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass

if __name__ == '__main__':
    alert_dic = {}
    # alert_dic = {"id": "Alert for Cpu Load:host=192-168-1-158", "status": 1}
    config_dic = {}
    config = configparser.ConfigParser()
    config.read("tickalert.conf")
    for section in config.sections():
        config_dic[section] = dict(config.items(section))
    sendmessage = SendMessages(config_dic)
    log = config_log(config_dic.get("LOG"))
    log.info("start init:\n{}".format(json.dumps(config_dic, indent=4, sort_keys=False, ensure_ascii=False)))
    host, port = config_dic.get("SERVER").get("ipaddr"), int(config_dic.get("SERVER").get("listen_port"))
    config_timer()
    try:
        # Single thread
        # server = HTTPServer((host, port), TodoHandler)

        # Multithreading
        server = ThreadingServer((host, port), TodoHandler)
    except OSError as e:
        print('OSError: [Errno {}] {}'.format(e.errno, e.strerror))
        sys.exit()
    if host:
        listen_host = host
    else:
        listen_host = '0.0.0.0'
    log.info("Starting server on {}:{}".format(listen_host, port))

    try:
        print("Starting server on {}:{}, use <Ctrl-C> to stop".format(listen_host, port))
        server.serve_forever()
    except KeyboardInterrupt:
        log.info('quit with <Ctrl-C>')
        print('<Ctrl-C>')
    except:
        log.error('quit with error:{}'.format(sys.exc_info()))
        print('unknown error')
